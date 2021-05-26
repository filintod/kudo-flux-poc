/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/metrics"
	"github.com/fluxcd/pkg/runtime/predicates"
	"github.com/fluxcd/pkg/untar"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/kudobuilder/kudo/pkg/apis/kudo/v1beta1"
	"github.com/kudobuilder/kudo/pkg/kudoctl/cmd/install"
	"github.com/kudobuilder/kudo/pkg/kudoctl/env"
	"github.com/spf13/afero"
	"io/ioutil"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	"net/http"
	"net/url"
	"os"
	"sigs.k8s.io/cli-utils/pkg/kstatus/polling"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kudov1 "github.com/kudobuilder/kudoflux/api/v1alpha1"
)

// RBAC for out CRD, for GitRepository and Buckets, and for ServiceAccount
// +kubebuilder:rbac:groups=flux.kudo.dev,resources=kudofluxes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=flux.kudo.dev,resources=kudofluxes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=flux.kudo.dev,resources=kudofluxes/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets;serviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=buckets;gitrepositories,verbs=get;list;watch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=buckets/status;gitrepositories/status,verbs=get
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Variables used by Kudo Operator
var (
	// initialization of filesystem for all commands
	fs = afero.NewOsFs()

	// Settings defines global flags and settings
	Settings env.Settings
)

// KudoFluxReconciler reconciles a KudoFlux object
type KudoFluxReconciler struct {
	client.Client
	httpClient            *retryablehttp.Client
	requeueDependency     time.Duration
	Log                   logr.Logger
	Scheme                *runtime.Scheme
	EventRecorder         record.EventRecorder
	ExternalEventRecorder *events.Recorder
	MetricsRecorder       *metrics.Recorder
	StatusPoller          *polling.StatusPoller
}

type KudoFluxReconcilerOptions struct {
	MaxConcurrentReconciles   int
	HTTPRetry                 int
	DependencyRequeueInterval time.Duration
}

// Reconcile reconciles our KudoFlux
func (r *KudoFluxReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logr.FromContext(ctx)
	reconcileStart := time.Now()

	// Get KudoFlux object this request refers to
	var kudo kudov1.KudoFlux
	if err := r.Get(ctx, req.NamespacedName, &kudo); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// records suspended metrics (following kustomize and helm controller)
	defer r.recordSuspension(ctx, kudo)

	// TODO: add finalizers (check helmcontrolelr or kustomize one)
	// Add our finalizer if it does not exist

	// Examine if the object is under deletion
	if !kudo.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, kudo)
	}

	if kudo.Spec.Suspend {
		log.Info("Reconciliation is suspended for this object")
		return ctrl.Result{}, nil
	}

	// resolve source reference
	source, err := r.getSource(ctx, kudo)
	if err != nil {
		if apierrors.IsNotFound(err) {
			msg := fmt.Sprintf("Source '%s' not found", kudo.Spec.SourceRef.String())
			return r.retrySourceNotReady(ctx, req, kudo, log, msg, "source")
		} else {
			// retry on transient errors
			return ctrl.Result{Requeue: true}, err
		}
	}

	if source.GetArtifact() == nil {
		msg := "Source is not ready, artifact not found"
		return r.retrySourceNotReady(ctx, req, kudo, log, msg, "artifact")
	}

	// record reconciliation duration
	if r.MetricsRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &kudo)
		if err != nil {
			return ctrl.Result{}, err
		}
		defer r.MetricsRecorder.RecordDuration(*objRef, reconcileStart)
	}

	// set the reconciliation status to progressing
	kudo = kudov1.KudoFluxProgressing(kudo)
	if err := r.patchStatus(ctx, req, kudo.Status); err != nil {
		log.Error(err, "unable to update status to progressing")
		return ctrl.Result{Requeue: true}, err
	}
	r.recordReadiness(ctx, kudo)

	// reconcile kudo by applying the latest revision
	reconciledKustomization, reconcileErr := r.reconcile(ctx, *kudo.DeepCopy(), source)
	if err := r.patchStatus(ctx, req, reconciledKustomization.Status); err != nil {
		log.Error(err, "unable to update status after reconciliation")
		return ctrl.Result{Requeue: true}, err
	}
	r.recordReadiness(ctx, reconciledKustomization)

	// broadcast the reconciliation failure and requeue at the specified retry interval
	if reconcileErr != nil {
		log.Error(reconcileErr, fmt.Sprintf("Reconciliation failed after %s, next try in %s",
			time.Now().Sub(reconcileStart).String(),
			kudo.GetRetryInterval().String()),
			"revision",
			source.GetArtifact().Revision)
		r.event(ctx, reconciledKustomization, source.GetArtifact().Revision, events.EventSeverityError,
			reconcileErr.Error(), nil)
		return ctrl.Result{RequeueAfter: kudo.GetRetryInterval()}, nil
	}

	// broadcast the reconciliation result and requeue at the specified interval
	log.Info(fmt.Sprintf("Reconciliation finished in %s, next run in %s",
		time.Now().Sub(reconcileStart).String(),
		kudo.Spec.Interval.Duration.String()),
		"revision",
		source.GetArtifact().Revision,
	)

	r.event(ctx, reconciledKustomization, source.GetArtifact().Revision, events.EventSeverityInfo,
		"Update completed", map[string]string{"commit_status": "update"})
	return ctrl.Result{RequeueAfter: kudo.Spec.Interval.Duration}, nil
}

// retrySourceNotReady is a helper to update readiness metric and kudoflux status when source or artifact in source are not ready
func (r *KudoFluxReconciler) retrySourceNotReady(ctx context.Context, req ctrl.Request, kudo kudov1.KudoFlux, log logr.Logger, msg, notFoundObject string) (ctrl.Result, error) {
	kudo = kudov1.KudoFluxNotReady(kudo, "", kudov1.ArtifactFailedReason, msg)
	if err := r.patchStatus(ctx, req, kudo.Status); err != nil {
		log.Error(err, fmt.Sprintf("unable to update status for %s not found", notFoundObject))
		return ctrl.Result{Requeue: true}, err
	}
	r.recordReadiness(ctx, kudo)
	log.Info(msg)
	// do not requeue immediately, when the source is created the watcher should trigger a reconciliation
	return ctrl.Result{RequeueAfter: kudo.GetRetryInterval()}, nil
}

// SetupWithManager sets up the controller with the Manager.  We have two options for Source Controller S3 compatible and GitRepository
// in a future we might want to have a Kudo Repository controller source to keep a local repository
// The controller watches for the sources, and Kudo Instances it owns
func (r *KudoFluxReconciler) SetupWithManager(mgr ctrl.Manager, opts KudoFluxReconcilerOptions) error {

	// setup reconciler with flag options
	r.requeueDependency = opts.DependencyRequeueInterval
	r.setupSourceHttpClient(opts)

	// Index KudoFlux  by the GitRepository references they (may) point at. This is needed as this resources are not owned
	// by the KudoFlux crd and we need a way to relate the source with the CRD
	if err := mgr.GetCache().IndexField(context.TODO(), &kudov1.KudoFlux{}, kudov1.GitRepositoryIndexKey,
		r.indexBy(sourcev1.GitRepositoryKind)); err != nil {
		return fmt.Errorf("failed setting index fields: %w", err)
	}

	// Index KudoFlux by the S3 compatible Bucket references they (may) point at. This is needed as this resources are not owned
	// by the KudoFlux crd and we need a way to relate the source with the CRD
	if err := mgr.GetCache().IndexField(context.TODO(), &kudov1.KudoFlux{}, kudov1.BucketIndexKey,
		r.indexBy(sourcev1.BucketKind)); err != nil {
		return fmt.Errorf("failed setting index fields: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&kudov1.KudoFlux{}, builder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{}),
		)).
		// KudoFlux Owns the Kudo Instance so any change would be captured in the reconciler
		Owns(&v1beta1.Instance{}).
		// KudoFlux watches for changes on the Source GitRepository objects related to this CRD
		Watches(
			&source.Kind{Type: &sourcev1.GitRepository{}},
			handler.EnqueueRequestsFromMapFunc(r.requestsForRevisionChangeOf(kudov1.GitRepositoryIndexKey)),
			builder.WithPredicates(SourceRevisionChangePredicate{}),
		).
		// KudoFlux watches for changes on the Source S3 compatible Bucket objects related to this CRD
		Watches(
			&source.Kind{Type: &sourcev1.Bucket{}},
			handler.EnqueueRequestsFromMapFunc(r.requestsForRevisionChangeOf(kudov1.BucketIndexKey)),
			builder.WithPredicates(SourceRevisionChangePredicate{}),
		).
		// We allow for multiple reconciles in parallel (default to 4 in main.go)
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}

// setupSourceHttpClient setups the HTTP retryable client to retrieve artifacts from the source controller used
func (r *KudoFluxReconciler) setupSourceHttpClient(opts KudoFluxReconcilerOptions) {
	// Configure the retryable http client used for fetching artifacts from the Source (GitRepository or S3).
	// By default it retries 10 times within a 3.5 minutes window.
	httpClient := retryablehttp.NewClient()
	httpClient.RetryWaitMin = 5 * time.Second
	httpClient.RetryWaitMax = 30 * time.Second
	httpClient.RetryMax = opts.HTTPRetry
	httpClient.Logger = nil
	r.httpClient = httpClient
}

// event creates a k8s event for the controller
func (r *KudoFluxReconciler) event(ctx context.Context, kudo kudov1.KudoFlux, revision, severity, msg string, metadata map[string]string) {
	log := logr.FromContext(ctx)
	r.EventRecorder.Event(&kudo, "Normal", severity, msg)
	objRef, err := reference.GetReference(r.Scheme, &kudo)
	if err != nil {
		log.Error(err, "unable to send event")
		return
	}

	if r.ExternalEventRecorder != nil {
		if metadata == nil {
			metadata = map[string]string{}
		}
		if revision != "" {
			metadata["revision"] = revision
		}

		reason := severity
		if c := apimeta.FindStatusCondition(kudo.Status.Conditions, meta.ReadyCondition); c != nil {
			reason = c.Reason
		}

		if err := r.ExternalEventRecorder.Eventf(*objRef, metadata, severity, reason, msg); err != nil {
			log.Error(err, "unable to send event")
			return
		}
	}
}

// recordReadiness set readiness condition gauge metric
func (r *KudoFluxReconciler) recordReadiness(ctx context.Context, kudo kudov1.KudoFlux) {
	if r.MetricsRecorder == nil {
		return
	}
	log := logr.FromContext(ctx)

	objRef, err := reference.GetReference(r.Scheme, &kudo)
	if err != nil {
		log.Error(err, "unable to record readiness metric")
		return
	}
	if rc := apimeta.FindStatusCondition(kudo.Status.Conditions, meta.ReadyCondition); rc != nil {
		r.MetricsRecorder.RecordCondition(*objRef, *rc, !kudo.DeletionTimestamp.IsZero())
	} else {
		r.MetricsRecorder.RecordCondition(*objRef, metav1.Condition{
			Type:   meta.ReadyCondition,
			Status: metav1.ConditionUnknown,
		}, !kudo.DeletionTimestamp.IsZero())
	}
}

// recordSuspension set suspension condition gauge metric
func (r *KudoFluxReconciler) recordSuspension(ctx context.Context, kudoflux kudov1.KudoFlux) {
	if r.MetricsRecorder == nil {
		return
	}
	log := logr.FromContext(ctx)

	objRef, err := reference.GetReference(r.Scheme, &kudoflux)
	if err != nil {
		log.Error(err, "unable to record suspended metric")
		return
	}

	if !kudoflux.DeletionTimestamp.IsZero() {
		r.MetricsRecorder.RecordSuspend(*objRef, false)
	} else {
		r.MetricsRecorder.RecordSuspend(*objRef, kudoflux.Spec.Suspend)
	}
}

func (r *KudoFluxReconciler) patchStatus(ctx context.Context, req ctrl.Request, newStatus kudov1.KudoFluxStatus) error {
	var kudo kudov1.KudoFlux
	if err := r.Get(ctx, req.NamespacedName, &kudo); err != nil {
		return err
	}

	patch := client.MergeFrom(kudo.DeepCopy())
	kudo.Status = newStatus

	return r.Status().Patch(ctx, &kudo, patch)
}

// download retrieves artifact from source controller using our http retryable client
func (r *KudoFluxReconciler) download(artifactURL string, tmpDir string) error {
	if hostname := os.Getenv("SOURCE_CONTROLLER_LOCALHOST"); hostname != "" {
		u, err := url.Parse(artifactURL)
		if err != nil {
			return err
		}
		u.Host = hostname
		artifactURL = u.String()
	}

	req, err := retryablehttp.NewRequest(http.MethodGet, artifactURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create a new request: %w", err)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download artifact, error: %w", err)
	}
	defer resp.Body.Close()

	// check response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download artifact from %s, status: %s", artifactURL, resp.Status)
	}

	// extract
	if _, err = untar.Untar(resp.Body, tmpDir); err != nil {
		return fmt.Errorf("failed to untar artifact, error: %w", err)
	}

	return nil
}

func (r *KudoFluxReconciler) getSource(ctx context.Context, kustomization kudov1.KudoFlux) (sourcev1.Source, error) {
	var source sourcev1.Source
	sourceNamespace := kustomization.GetNamespace()
	if kustomization.Spec.SourceRef.Namespace != "" {
		sourceNamespace = kustomization.Spec.SourceRef.Namespace
	}
	namespacedName := types.NamespacedName{
		Namespace: sourceNamespace,
		Name:      kustomization.Spec.SourceRef.Name,
	}
	switch kustomization.Spec.SourceRef.Kind {
	case sourcev1.GitRepositoryKind:
		var repository sourcev1.GitRepository
		err := r.Client.Get(ctx, namespacedName, &repository)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return source, err
			}
			return source, fmt.Errorf("unable to get source '%s': %w", namespacedName, err)
		}
		source = &repository
	case sourcev1.BucketKind:
		var bucket sourcev1.Bucket
		err := r.Client.Get(ctx, namespacedName, &bucket)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return source, err
			}
			return source, fmt.Errorf("unable to get source '%s': %w", namespacedName, err)
		}
		source = &bucket
	default:
		return source, fmt.Errorf("source `%s` kind '%s' not supported",
			kustomization.Spec.SourceRef.Name, kustomization.Spec.SourceRef.Kind)
	}
	return source, nil
}

func (r *KudoFluxReconciler) reconcileDelete(ctx context.Context, kudo kudov1.KudoFlux) (ctrl.Result, error) {
	log := logr.FromContext(ctx)
	if kudo.Spec.Prune && !kudo.Spec.Suspend {
		// create any necessary kube-clients
		imp := NewKudoImpersonation(kudo, r.Client, r.StatusPoller, "")
		client, _, err := imp.GetClient(ctx)
		if err != nil {
			err = fmt.Errorf("failed to build kube client for Kustomization: %w", err)
			log.Error(err, "Unable to prune for finalizer")
			return ctrl.Result{}, err
		}
		if err := r.prune(ctx, client, kudo); err != nil {
			r.event(ctx, kudo, kudo.Status.LastAppliedRevision, events.EventSeverityError, "pruning for deleted resource failed", nil)
			// Return the error so we retry the failed garbage collection
			return ctrl.Result{}, err
		}
	}

	// Record deleted status
	r.recordReadiness(ctx, kudo)

	// Remove our finalizer from the list and update it
	controllerutil.RemoveFinalizer(&kudo, kudov1.KudoFinalizer)
	if err := r.Update(ctx, &kudo); err != nil {
		return ctrl.Result{}, err
	}

	// Stop reconciliation as the object is being deleted
	return ctrl.Result{}, nil
}

// TODO: implement deletion of Instance
func (r *KudoFluxReconciler) prune(ctx context.Context, c client.Client, kudo kudov1.KudoFlux) error {
	log := logr.FromContext(ctx)
	if !kudo.Spec.Prune {
		return nil
	}
	if kudo.DeletionTimestamp.IsZero() {
		return nil
	}

	log.Info("prune (deletion) not implemented!!!")
	return nil
}

func (r *KudoFluxReconciler) reconcile(ctx context.Context, kudo kudov1.KudoFlux, source sourcev1.Source) (kudov1.KudoFlux, error) {
	// record the value of the reconciliation request, if any
	if v, ok := meta.ReconcileAnnotationValue(kudo.GetAnnotations()); ok {
		kudo.Status.SetLastHandledReconcileRequest(v)
	}

	// create tmp dir
	tmpDir, err := ioutil.TempDir("", kudo.Name)
	if err != nil {
		err = fmt.Errorf("tmp dir error: %w", err)
		return kudov1.KudoFluxNotReady(
			kudo,
			source.GetArtifact().Revision,
			sourcev1.StorageOperationFailedReason,
			err.Error(),
		), err
	}
	defer os.RemoveAll(tmpDir)

	// download artifact and extract files
	err = r.download(source.GetArtifact().URL, tmpDir)
	if err != nil {
		return kudov1.KudoFluxNotReady(
			kudo,
			source.GetArtifact().Revision,
			kudov1.ArtifactFailedReason,
			err.Error(),
		), err
	}

	// check build path exists
	dirPath, err := securejoin.SecureJoin(tmpDir, kudo.Spec.Operator.Spec.Package)
	if err != nil {
		return kudov1.KudoFluxNotReady(
			kudo,
			source.GetArtifact().Revision,
			kudov1.ArtifactFailedReason,
			err.Error(),
		), err
	}
	if _, err := os.Stat(dirPath); err != nil {
		err = fmt.Errorf("kudo path not found: %w", err)
		return kudov1.KudoFluxNotReady(
			kudo,
			source.GetArtifact().Revision,
			kudov1.ArtifactFailedReason,
			err.Error(),
		), err
	}

	// create any necessary kube-clients for impersonation
	impersonation := NewKudoImpersonation(kudo, r.Client, r.StatusPoller, dirPath)
	// TODO: use statusPoller in health check below
	//kubeClient, statusPoller, err := impersonation.GetClient(ctx)
	kubeClient, _, err := impersonation.GetClient(ctx)
	if err != nil {
		return kudov1.KudoFluxNotReady(
			kudo,
			source.GetArtifact().Revision,
			meta.ReconciliationFailedReason,
			err.Error(),
		), fmt.Errorf("failed to build kube client: %w", err)
	}

	// generate kudo.yaml and calculate the manifests checksum
	err = install.Run([]string{dirPath}, &install.Options{
		InstanceName:    kudo.Name,
		Parameters:      kudo.GetParameters(),
		AppVersion:      kudo.GetAppVersion(),
		OperatorVersion: kudo.GetOperatorVersion(),
		SkipInstance:    false,
		Wait:            true,
		WaitTime:        int64(kudo.GetTimeout().Seconds()),
		CreateNameSpace: false,
		InCluster:       false,
	}, fs, &Settings)
	if err != nil {
		return kudov1.KudoFluxNotReady(
			kudo,
			source.GetArtifact().Revision,
			kudov1.InstalledFailedReason,
			err.Error(),
		), err
	}

	//// dry-run apply
	//err = r.validate(ctx, kudo, impersonation, dirPath)
	//if err != nil {
	//	return kudov1.KudoFluxNotReady(
	//		kudo,
	//		source.GetArtifact().Revision,
	//		kudov1.ValidationFailedReason,
	//		err.Error(),
	//	), err
	//}

	// prune
	err = r.prune(ctx, kubeClient, kudo)
	// TODO: prune (clean plan)
	//if err != nil {
	//	return kudov1.KudoFluxNotReady(
	//		kudo,
	//		source.GetArtifact().Revision,
	//		kudov1.PruneFailedReason,
	//		err.Error(),
	//	), err
	//}

	// TODO: check Health (KUTTL)
	// health assessment
	//err = r.checkHealth(ctx, statusPoller, kudo, source.GetArtifact().Revision, changeSet != "")
	//if err != nil {
	//	return kudov1.KudoFluxNotReady(
	//		kudo,
	//		source.GetArtifact().Revision,
	//		kudov1.HealthCheckFailedReason,
	//		err.Error(),
	//	), err
	//}

	return kudov1.KudoFluxReady(
		kudo,
		source.GetArtifact().Revision,
		meta.ReconciliationSucceededReason,
		"Applied revision: "+source.GetArtifact().Revision,
	), nil
}
