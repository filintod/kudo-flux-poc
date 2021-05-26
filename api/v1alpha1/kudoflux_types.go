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

package v1alpha1

import (
	"encoding/json"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/dependency"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"time"
)

const (
	KudoKind                  = "KudoFlux"
	KudoFinalizer             = "finalizers.fluxcd.io"
	MaxConditionMessageLength = 20000
	DisabledValue             = "disabled"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// KudoFluxSpec defines the desired state of KudoFlux
type KudoFluxSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Instance defines the template of the v1beta1.KudoChart that should be created
	// for this Kudo Instance.
	// +required
	Operator OperatorTemplate `json:"operator"`

	// Interval at which to reconcile the Helm release.
	// +required
	Interval metav1.Duration `json:"interval"`

	// The interval at which to retry a previously failed reconciliation.
	// When not specified, the controller uses the KustomizationSpec.Interval
	// value to retry failures.
	// +optional
	RetryInterval *metav1.Duration `json:"retryInterval,omitempty"`

	// KubeConfig for reconciling the HelmRelease on a remote cluster.
	// When specified, KubeConfig takes precedence over ServiceAccountName.
	// +optional
	KubeConfig *KubeConfig `json:"kubeConfig,omitempty"`

	// Suspend tells the controller to suspend reconciliation for this HelmRelease,
	// it does not apply to already started reconciliations. Defaults to false.
	// +optional
	Suspend bool `json:"suspend,omitempty"`

	// Prune enables garbage collection of Kudo Instance if this is deleted
	// +required
	Prune bool `json:"prune"`

	// InstanceName used for the Operator Instance. Defaults to a composition of
	// '[TargetNamespace-]Name'.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=53
	// +kubebuilder:validation:Optional
	// +optional
	Instance string `json:"instance,omitempty"`

	// TargetNamespace to target when performing operations for the HelmRelease.
	// Defaults to the namespace of the HelmRelease.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Optional
	// +optional
	TargetNamespace string `json:"targetNamespace,omitempty"`

	// DependsOn may contain a dependency.CrossNamespaceDependencyReference slice with
	// references to KudoFlux resources that must be ready before this KudoFlux
	// can be reconciled.
	// +optional
	DependsOn []dependency.CrossNamespaceDependencyReference `json:"dependsOn,omitempty"`

	// Timeout is the time to wait for the install to complete individual Kubernetes operation (like Jobs
	// for hooks) during the performance of a Helm action. Defaults to '5m0s'.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// The name of the Kubernetes service account to impersonate
	// when reconciling this HelmRelease.
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// Reference of the source where the kudo operator is.
	// +required
	SourceRef CrossNamespaceObjectReference `json:"sourceRef"`

	// Deploy holds the configuration for Kudo install actions for this KudoInstance.
	// +optional
	Deploy *Deploy `json:"install,omitempty"`

	// Upgrade holds the configuration for Kudo upgrade actions for this KudoInstance.
	// +optional
	Upgrade *Upgrade `json:"upgrade,omitempty"`

	// Test holds the configuration for Kudo test actions for this KudoInstance.
	// +optional
	Test *Test `json:"test,omitempty"`

	// Update holds the configuration for Kudo update actions for this KudoInstance.
	// +optional
	Update *Update `json:"update,omitempty"`

	//// Update holds the configuration for Kudo rollback actions for this KudoInstance.
	//// +optional
	//Trigger *Trigger `json:"trigger,omitempty"`
	//
	//// Uninstall holds the configuration for Kudo uninstall actions for this KudoInstance.
	//// +optional
	//Uninstall *Uninstall `json:"uninstall,omitempty"`

	// Parameters Overrides

	// ParametersFrom holds references to resources containing Kudo values for this KudoInstance,
	// and information about how they should be merged.
	ParametersFrom []ParametersReference `json:"valuesFrom,omitempty"`

	// Parameters holds the values for this Kudo release.
	// +optional
	Parameters *apiextensionsv1.JSON `json:"values,omitempty"`
}

// GetInstall returns the configuration for Kudo install actions for the
// KudoInstance.
func (in KudoFluxSpec) GetDeploy() Deploy {
	if in.Deploy == nil {
		return Deploy{}
	}
	return *in.Deploy
}

// GetUpgrade returns the configuration for Kudo upgrade actions for this
// KudoInstance.
func (in KudoFluxSpec) GetUpgrade() Upgrade {
	if in.Upgrade == nil {
		return Upgrade{}
	}
	return *in.Upgrade
}

// GetTest returns the configuration for Kudo test actions for this KudoInstance.
func (in KudoFluxSpec) GetTest() Test {
	if in.Test == nil {
		return Test{}
	}
	return *in.Test
}

// GetRollback returns the configuration for Kudo rollback actions for this
// KudoInstance.
func (in KudoFluxSpec) GetUpdate() Update {
	if in.Update == nil {
		return Update{}
	}
	return *in.Update
}

//// GetUninstall returns the configuration for Kudo uninstall actions for this
//// KudoInstance.
//func (in KudoFluxSpec) GetUninstall() Uninstall {
//	if in.Uninstall == nil {
//		return Uninstall{}
//	}
//	return *in.Uninstall
//}

// KubeConfig references a Kubernetes secret that contains a kubeconfig file.
type KubeConfig struct {
	// SecretRef holds the name to a secret that contains a 'value' key with
	// the kubeconfig file as the value. It must be in the same namespace as
	// the KudoInstance.
	// It is recommended that the kubeconfig is self-contained, and the secret
	// is regularly updated if credentials such as a cloud-access-token expire.
	// Cloud specific `cmd-path` auth helpers will not function without adding
	// binaries and credentials to the Pod that is responsible for reconciling
	// the KudoInstance.
	// +required
	SecretRef meta.LocalObjectReference `json:"secretRef,omitempty"`
}

// OperatorTemplate defines the template from which the controller will
// generate a v1alpha1.Instance object in the same namespace as the referenced
// v1beta1.Source.
type OperatorTemplate struct {
	// Spec holds the template for the v1beta1.HelmChartSpec for this HelmRelease.
	// +required
	Spec Instance `json:"spec"`
}

// Instance defines the desired state of the Instance.
type Instance struct {
	// The name or path the Package in the repository that is available at in the SourceRef.
	// +required
	Package string `json:"package"`

	// OperatorVersion ignored for operators from v1beta1.GitRepository and
	// v1beta1.Bucket sources.
	// +optional
	OperatorVersion string `json:"version,omitempty"`

	// a specific app version in the official repo, defaults to the most recent
	// +optional
	AppVersion string `json:"appVersion,omitempty"`

	// The name and namespace of the v1beta1.Source the chart is available at.
	// +required
	SourceRef CrossNamespaceObjectReference `json:"sourceRef"`

	// Interval at which to check the v1beta1.Source for updates. Defaults to
	// 'HelmReleaseSpec.Interval'.
	// +optional
	Interval *metav1.Duration `json:"interval,omitempty"`

	// Alternative list of parameter files to use as the instance parameters
	// is not included by default), expected to be a relative path in the SourceRef.
	// Values files are merged in the order of this list with the last file overriding
	// the first. Ignored when omitted.
	// +optional
	ParameterFiles []string `json:"parameterFiles,omitempty"`
}

// GetInterval returns the configured interval for the v1beta1.HelmChart,
// or the given default.
func (in OperatorTemplate) GetInterval(defaultInterval metav1.Duration) metav1.Duration {
	if in.Spec.Interval == nil {
		return defaultInterval
	}
	return *in.Spec.Interval
}

// GetNamespace returns the namespace targeted namespace for the
// v1beta1.HelmChart, or the given default.
func (in OperatorTemplate) GetNamespace(defaultNamespace string) string {
	if in.Spec.SourceRef.Namespace == "" {
		return defaultNamespace
	}
	return in.Spec.SourceRef.Namespace
}

// DeploymentAction defines a consistent interface for Deploy, Upgrade and Update.
// +kubebuilder:object:generate=false
type DeploymentAction interface {
	GetDescription() string
	GetRemediation() Remediation
}

// Remediation defines a consistent interface for DeployRemediation, UpgradeRemediation and UpdateRemediation
// +kubebuilder:object:generate=false
type Remediation interface {
	GetRetries() int
	MustIgnoreTestFailures(bool) bool
	MustRemediateLastFailure() bool
	GetStrategy() RemediationStrategy
	GetFailureCount(hr KudoFlux) int64
	IncrementFailureCount(hr *KudoFlux)
	RetriesExhausted(hr KudoFlux) bool
}

// Deploy holds the configuration for Helm install actions performed for this
// HelmRelease.
type Deploy struct {
	// Timeout is the time to wait for any individual Kubernetes operation (like
	// Jobs for hooks) during the performance of a Helm install action. Defaults to
	// 'HelmReleaseSpec.Timeout'.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// Remediation holds the remediation configuration for when the Helm install
	// action for the HelmRelease fails. The default is to not perform any action.
	// +optional
	Remediation *DeployRemediation `json:"remediation,omitempty"`

	// DisableWait disables the waiting for resources to be ready after a Helm
	// install has been performed.
	// +optional
	DisableWait bool `json:"disableWait,omitempty"`

	// Replace tells the Helm install action to re-use the 'ReleaseName', but only
	// if that name is a deleted release which remains in the history.
	// +optional
	Replace bool `json:"replace,omitempty"`

	// CRDs upgrade CRDs from the Helm Chart's crds directory according
	// to the CRD upgrade policy provided here. Valid values are `Skip`,
	// `Create` or `CreateReplace`. Default is `Create` and if omitted
	// CRDs are installed but not updated.
	//
	// Skip: do neither install nor replace (update) any CRDs.
	//
	// Create: new CRDs are created, existing CRDs are neither updated nor deleted.
	//
	// CreateReplace: new CRDs are created, existing CRDs are updated (replaced)
	// but not deleted.
	//
	// By default, CRDs are applied (installed) during Helm install action.
	// With this option users can opt-in to CRD replace existing CRDs on Helm
	// install actions, which is not (yet) natively supported by Helm.
	// https://helm.sh/docs/chart_best_practices/custom_resource_definitions.
	//
	// +kubebuilder:validation:Enum=Skip;Create;CreateReplace
	// +optional
	CRDs CRDsPolicy `json:"crds,omitempty"`

	// CreateNamespace tells the Helm install action to create the
	// HelmReleaseSpec.TargetNamespace if it does not exist yet.
	// On uninstall, the namespace will not be garbage collected.
	// +optional
	CreateNamespace bool `json:"createNamespace,omitempty"`
}

// GetTimeout returns the configured timeout for the Helm install action,
// or the given default.
func (in Deploy) GetTimeout(defaultTimeout metav1.Duration) metav1.Duration {
	if in.Timeout == nil {
		return defaultTimeout
	}
	return *in.Timeout
}

// GetDescription returns a description for the Helm install action.
func (in Deploy) GetDescription() string {
	return "install"
}

// GetRemediation returns the configured Remediation for the Helm install action.
func (in Deploy) GetRemediation() Remediation {
	if in.Remediation == nil {
		return DeployRemediation{}
	}
	return *in.Remediation
}

// DeployRemediation holds the configuration for Helm install remediation.
type DeployRemediation struct {
	// Retries is the number of retries that should be attempted on failures before
	// bailing. Remediation, using an uninstall, is performed between each attempt.
	// Defaults to '0', a negative integer equals to unlimited retries.
	// +optional
	Retries int `json:"retries,omitempty"`

	// IgnoreTestFailures tells the controller to skip remediation when the Helm
	// tests are run after an install action but fail. Defaults to
	// 'Test.IgnoreFailures'.
	// +optional
	IgnoreTestFailures *bool `json:"ignoreTestFailures,omitempty"`

	// RemediateLastFailure tells the controller to remediate the last failure, when
	// no retries remain. Defaults to 'false'.
	// +optional
	RemediateLastFailure *bool `json:"remediateLastFailure,omitempty"`
}

// GetRetries returns the number of retries that should be attempted on
// failures.
func (in DeployRemediation) GetRetries() int {
	return in.Retries
}

// MustIgnoreTestFailures returns the configured IgnoreTestFailures or the given
// default.
func (in DeployRemediation) MustIgnoreTestFailures(def bool) bool {
	if in.IgnoreTestFailures == nil {
		return def
	}
	return *in.IgnoreTestFailures
}

// MustRemediateLastFailure returns whether to remediate the last failure when
// no retries remain.
func (in DeployRemediation) MustRemediateLastFailure() bool {
	if in.RemediateLastFailure == nil {
		return false
	}
	return *in.RemediateLastFailure
}

// GetStrategy returns the strategy to use for failure remediation.
func (in DeployRemediation) GetStrategy() RemediationStrategy {
	return UninstallRemediationStrategy
}

// GetFailureCount gets the failure count.
func (in DeployRemediation) GetFailureCount(hr KudoFlux) int64 {
	return hr.Status.DeployFailures
}

// IncrementFailureCount increments the failure count.
func (in DeployRemediation) IncrementFailureCount(hr *KudoFlux) {
	hr.Status.DeployFailures++
}

// RetriesExhausted returns true if there are no remaining retries.
func (in DeployRemediation) RetriesExhausted(hr KudoFlux) bool {
	return in.Retries >= 0 && in.GetFailureCount(hr) > int64(in.Retries)
}

// CRDsPolicy defines the install/upgrade approach to use for CRDs when
// installing or upgrading a HelmRelease.
type CRDsPolicy string

const (
	// Skip CRDs do neither install nor replace (update) any CRDs.
	Skip CRDsPolicy = "Skip"
	// Create CRDs which do not already exist, do not replace (update) already existing
	// CRDs and keep (do not delete) CRDs which no longer exist in the current release.
	Create CRDsPolicy = "Create"
	// CreateReplace CRDs which do not already exist, Replace (update) already existing CRDs
	// and keep (do not delete) CRDs which no longer exist in the current release.
	CreateReplace CRDsPolicy = "CreateReplace"
)

// Upgrade holds the configuration for Helm upgrade actions for this
// HelmRelease.
type Upgrade struct {
	// Timeout is the time to wait for any individual Kubernetes operation (like
	// Jobs for hooks) during the performance of a Helm upgrade action. Defaults to
	// 'HelmReleaseSpec.Timeout'.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// Remediation holds the remediation configuration for when the Helm upgrade
	// action for the HelmRelease fails. The default is to not perform any action.
	// +optional
	Remediation *UpgradeRemediation `json:"remediation,omitempty"`

	// DisableWait disables the waiting for resources to be ready after a Helm
	// upgrade has been performed.
	// +optional
	DisableWait bool `json:"disableWait,omitempty"`

	// DisableOpenAPIValidation prevents the Helm upgrade action from validating
	// rendered templates against the Kubernetes OpenAPI Schema.
	// +optional
	DisableOpenAPIValidation bool `json:"disableOpenAPIValidation,omitempty"`

	// Force forces resource updates through a replacement strategy.
	// +optional
	Force bool `json:"force,omitempty"`

	// PreserveValues will make Helm reuse the last release's values and merge in
	// overrides from 'Values'. Setting this flag makes the HelmRelease
	// non-declarative.
	// +optional
	PreserveValues bool `json:"preserveValues,omitempty"`

	// CleanupOnFail allows deletion of new resources created during the Helm
	// upgrade action when it fails.
	// +optional
	CleanupOnFail bool `json:"cleanupOnFail,omitempty"`

	// CRDs upgrade CRDs from the Helm Chart's crds directory according
	// to the CRD upgrade policy provided here. Valid values are `Skip`,
	// `Create` or `CreateReplace`. Default is `Skip` and if omitted
	// CRDs are neither installed nor upgraded.
	//
	// Skip: do neither install nor replace (update) any CRDs.
	//
	// Create: new CRDs are created, existing CRDs are neither updated nor deleted.
	//
	// CreateReplace: new CRDs are created, existing CRDs are updated (replaced)
	// but not deleted.
	//
	// By default, CRDs are not applied during Helm upgrade action. With this
	// option users can opt-in to CRD upgrade, which is not (yet) natively supported by Helm.
	// https://helm.sh/docs/chart_best_practices/custom_resource_definitions.
	//
	// +kubebuilder:validation:Enum=Skip;Create;CreateReplace
	// +optional
	CRDs CRDsPolicy `json:"crds,omitempty"`
}

// GetTimeout returns the configured timeout for the Helm upgrade action, or the
// given default.
func (in Upgrade) GetTimeout(defaultTimeout metav1.Duration) metav1.Duration {
	if in.Timeout == nil {
		return defaultTimeout
	}
	return *in.Timeout
}

// GetDescription returns a description for the Helm upgrade action.
func (in Upgrade) GetDescription() string {
	return "upgrade"
}

// GetRemediation returns the configured Remediation for the Helm upgrade
// action.
func (in Upgrade) GetRemediation() Remediation {
	if in.Remediation == nil {
		return UpgradeRemediation{}
	}
	return *in.Remediation
}

// UpgradeRemediation holds the configuration for Helm upgrade remediation.
type UpgradeRemediation struct {
	// Retries is the number of retries that should be attempted on failures before
	// bailing. Remediation, using 'Strategy', is performed between each attempt.
	// Defaults to '0', a negative integer equals to unlimited retries.
	// +optional
	Retries int `json:"retries,omitempty"`

	// IgnoreTestFailures tells the controller to skip remediation when the Helm
	// tests are run after an upgrade action but fail.
	// Defaults to 'Test.IgnoreFailures'.
	// +optional
	IgnoreTestFailures *bool `json:"ignoreTestFailures,omitempty"`

	// RemediateLastFailure tells the controller to remediate the last failure, when
	// no retries remain. Defaults to 'false' unless 'Retries' is greater than 0.
	// +optional
	RemediateLastFailure *bool `json:"remediateLastFailure,omitempty"`

	// Strategy to use for failure remediation. Defaults to 'rollback'.
	// +kubebuilder:validation:Enum=rollback;uninstall
	// +optional
	Strategy *RemediationStrategy `json:"strategy,omitempty"`
}

// GetRetries returns the number of retries that should be attempted on
// failures.
func (in UpgradeRemediation) GetRetries() int {
	return in.Retries
}

// MustIgnoreTestFailures returns the configured IgnoreTestFailures or the given
// default.
func (in UpgradeRemediation) MustIgnoreTestFailures(def bool) bool {
	if in.IgnoreTestFailures == nil {
		return def
	}
	return *in.IgnoreTestFailures
}

// MustRemediateLastFailure returns whether to remediate the last failure when
// no retries remain.
func (in UpgradeRemediation) MustRemediateLastFailure() bool {
	if in.RemediateLastFailure == nil {
		return in.Retries > 0
	}
	return *in.RemediateLastFailure
}

// GetStrategy returns the strategy to use for failure remediation.
func (in UpgradeRemediation) GetStrategy() RemediationStrategy {
	if in.Strategy == nil {
		return RollbackRemediationStrategy
	}
	return *in.Strategy
}

// GetFailureCount gets the failure count.
func (in UpgradeRemediation) GetFailureCount(hr KudoFlux) int64 {
	return hr.Status.UpgradeFailures
}

// IncrementFailureCount increments the failure count.
func (in UpgradeRemediation) IncrementFailureCount(hr *KudoFlux) {
	hr.Status.UpgradeFailures++
}

// RetriesExhausted returns true if there are no remaining retries.
func (in UpgradeRemediation) RetriesExhausted(hr KudoFlux) bool {
	return in.Retries >= 0 && in.GetFailureCount(hr) > int64(in.Retries)
}

// RemediationStrategy returns the strategy to use to remediate a failed install
// or upgrade.
type RemediationStrategy string

const (
	// RollbackRemediationStrategy represents a Helm remediation strategy of Helm
	// rollback.
	RollbackRemediationStrategy RemediationStrategy = "rollback"

	// UninstallRemediationStrategy represents a Helm remediation strategy of Helm
	// uninstall.
	UninstallRemediationStrategy RemediationStrategy = "uninstall"
)

// Test holds the configuration for Helm test actions for this HelmRelease.
type Test struct {
	// Enable enables Helm test actions for this HelmRelease after an Helm install
	// or upgrade action has been performed.
	// +optional
	Enable bool `json:"enable,omitempty"`

	// Timeout is the time to wait for any individual Kubernetes operation during
	// the performance of a Helm test action. Defaults to 'HelmReleaseSpec.Timeout'.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// IgnoreFailures tells the controller to skip remediation when the Helm tests
	// are run but fail. Can be overwritten for tests run after install or upgrade
	// actions in 'Deploy.IgnoreTestFailures' and 'Upgrade.IgnoreTestFailures'.
	// +optional
	IgnoreFailures bool `json:"ignoreFailures,omitempty"`
}

// GetTimeout returns the configured timeout for the Helm test action,
// or the given default.
func (in Test) GetTimeout(defaultTimeout metav1.Duration) metav1.Duration {
	if in.Timeout == nil {
		return defaultTimeout
	}
	return *in.Timeout
}

// Update holds the configuration for Helm rollback actions for this
// HelmRelease.
type Update struct {
	// Timeout is the time to wait for any individual Kubernetes operation (like
	// Jobs for hooks) during the performance of a Helm rollback action. Defaults to
	// 'HelmReleaseSpec.Timeout'.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// DisableWait disables the waiting for resources to be ready after a Helm
	// rollback has been performed.
	// +optional
	DisableWait bool `json:"disableWait,omitempty"`

	// DisableHooks prevents hooks from running during the Helm rollback action.
	// +optional
	DisableHooks bool `json:"disableHooks,omitempty"`

	// Recreate performs pod restarts for the resource if applicable.
	// +optional
	Recreate bool `json:"recreate,omitempty"`

	// Force forces resource updates through a replacement strategy.
	// +optional
	Force bool `json:"force,omitempty"`

	// CleanupOnFail allows deletion of new resources created during the Helm
	// rollback action when it fails.
	// +optional
	CleanupOnFail bool `json:"cleanupOnFail,omitempty"`
}

// GetTimeout returns the configured timeout for the Helm rollback action, or
// the given default.
func (in Update) GetTimeout(defaultTimeout metav1.Duration) metav1.Duration {
	if in.Timeout == nil {
		return defaultTimeout
	}
	return *in.Timeout
}

// KudoFluxStatus defines the observed state of KudoFlux
type KudoFluxStatus struct {
	// ObservedGeneration is the last reconciled generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// The last successfully applied revision.
	// The revision format for Git sources is <branch|tag>/<commit-sha>.
	// +optional
	LastAppliedRevision string `json:"lastAppliedRevision,omitempty"`

	// LastAttemptedRevision is the revision of the last reconciliation attempt.
	// +optional
	LastAttemptedRevision string `json:"lastAttemptedRevision,omitempty"`

	meta.ReconcileRequestStatus `json:",inline"`

	// LastInstanceRevision is the revision of the last successful .
	// +optional
	LastInstanceRevision int `json:"lastInstanceRevision,omitempty"`

	// Instance is the namespaced The Instance name. (defaults to Operator name appended with -instance).
	// +optional
	Instance string `json:"instance,omitempty"`

	// Failures is the reconciliation failure count against the latest desired
	// state. It is reset after a successful reconciliation.
	// +optional
	Failures int64 `json:"failures,omitempty"`

	// DeployFailures is the install failure count against the latest desired
	// state. It is reset after a successful reconciliation.
	// +optional
	DeployFailures int64 `json:"installFailures,omitempty"`

	// UpgradeFailures is the upgrade failure count against the latest desired
	// state. It is reset after a successful reconciliation.
	// +optional
	UpgradeFailures int64 `json:"upgradeFailures,omitempty"`

	// UpdateFailures is the update failure count against the latest desired
	// state. It is reset after a successful reconciliation.
	// +optional
	UpdateFailures int64 `json:"updateFailures,omitempty"`
}

const (
	// GitRepositoryIndexKey is the key used for indexing kustomizations
	// based on their Git sources.
	GitRepositoryIndexKey string = ".metadata.gitRepository"
	// BucketIndexKey is the key used for indexing kustomizations
	// based on their S3 sources.
	BucketIndexKey string = ".metadata.bucket"
)

// KustomizationProgressing resets the conditions of the given Kustomization to a single
// ReadyCondition with status ConditionUnknown.
func KudoFluxProgressing(k KudoFlux) KudoFlux {
	meta.SetResourceCondition(&k, meta.ReadyCondition, metav1.ConditionUnknown, meta.ProgressingReason, "reconciliation in progress")
	return k
}

// SetKustomizeReadiness sets the ReadyCondition, ObservedGeneration, and LastAttemptedRevision,
// on the KudoFlux.
func SetKudoFluxReadiness(k *KudoFlux, status metav1.ConditionStatus, reason, message string, revision string) {
	meta.SetResourceCondition(k, meta.ReadyCondition, status, reason, trimString(message, MaxConditionMessageLength))
	k.Status.ObservedGeneration = k.Generation
	k.Status.LastAttemptedRevision = revision
}

// KudoFluxNotReady registers a failed apply attempt of the given KudoFlux.
func KudoFluxNotReady(k KudoFlux, revision, reason, message string) KudoFlux {
	SetKudoFluxReadiness(&k, metav1.ConditionFalse, reason, trimString(message, MaxConditionMessageLength), revision)
	if revision != "" {
		k.Status.LastAttemptedRevision = revision
	}
	return k
}

// KudoFluxReady registers a successful apply attempt of the given KudoFlux.
func KudoFluxReady(k KudoFlux, revision, reason, message string) KudoFlux {
	SetKudoFluxReadiness(&k, metav1.ConditionTrue, reason, trimString(message, MaxConditionMessageLength), revision)
	k.Status.LastAppliedRevision = revision
	return k
}

// GetTimeout returns the timeout with default.
func (in KudoFlux) GetTimeout() time.Duration {
	duration := in.Spec.Interval.Duration
	if in.Spec.Timeout != nil {
		duration = in.Spec.Timeout.Duration
	}
	if duration < time.Minute {
		return time.Minute
	}
	return duration
}

// GetRetryInterval returns the retry interval
func (in KudoFlux) GetRetryInterval() time.Duration {
	if in.Spec.RetryInterval != nil {
		return in.Spec.RetryInterval.Duration
	}
	return in.Spec.Interval.Duration
}

func (in KudoFlux) GetDependsOn() (types.NamespacedName, []dependency.CrossNamespaceDependencyReference) {
	return types.NamespacedName{
		Namespace: in.Namespace,
		Name:      in.Name,
	}, in.Spec.DependsOn
}

// GetStatusConditions returns a pointer to the Status.Conditions slice
func (in *KudoFlux) GetStatusConditions() *[]metav1.Condition {
	return &in.Status.Conditions
}

// GetParameters unmarshals the raw values to a map[string]string and returns the result.
func (in KudoFlux) GetParameters() map[string]string {
	var values map[string]string
	if in.Spec.Parameters != nil {
		_ = json.Unmarshal(in.Spec.Parameters.Raw, &values)
	}
	return values
}

// GetAppVersion gets the AppVersion for the Kudo Operator
func (in KudoFlux) GetAppVersion() string {
	return in.Spec.Operator.Spec.AppVersion
}

// GetOperatorVersion gets the OperatorVersion for the Kudo Operator
func (in KudoFlux) GetOperatorVersion() string {
	return in.Spec.Operator.Spec.OperatorVersion
}

//+genclient
//+kubebuilder:object:root=true
//+kubebuilder:resource:shortName=ki
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
//+kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message",description=""
//+kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// KudoFlux is the Schema for the kudofluxes API
type KudoFlux struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KudoFluxSpec   `json:"spec,omitempty"`
	Status KudoFluxStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// KudoFluxList contains a list of KudoFlux
type KudoFluxList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KudoFlux `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KudoFlux{}, &KudoFluxList{})
}

func trimString(str string, limit int) string {
	result := str
	chars := 0
	for i := range str {
		if chars >= limit {
			result = str[:i] + "..."
			break
		}
		chars++
	}
	return result
}
