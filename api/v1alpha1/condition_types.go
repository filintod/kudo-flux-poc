/*
Copyright 2020 The Flux authors

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

// Status Conditions and Reasons to complement Flux meta
// conditions pkg (https://github.com/fluxcd/pkg/blob/main/apis/meta/conditions.go)

const (
	// DeployedCondition is the condition
	// to record the last Deploy/Upgrade/Update assessment result.
	DeployedCondition string = "Deployed"

	// TestSuccessCondition represents the status of the last test attempt against
	// the latest desired state.
	TestSuccessCondition string = "TestSuccess"

	// RemediatedCondition represents the status of the last remediation attempt
	// (uninstall/rollback) due to a failure of the last release attempt against the
	// latest desired state.
	RemediatedCondition string = "Remediated"
)

const (
	// HealthCheckFailedReason represents the fact that
	// one of the health checks failed.
	HealthCheckFailedReason string = "HealthCheckFailed"

	// VerificationFailedReason represents the fact that the
	// validation of the manifests has failed (kudo package verify).
	VerificationFailedReason string = "VerificationFailed"

	// InstalledFailedReason represents the fact that the
	// installation of the manifests has failed (kudo package verify).
	InstalledFailedReason string = "InstallationFailed"

	// ArtifactFailedReason represents the fact that the
	// artifact download of the operator failed.
	ArtifactFailedReason string = "ArtifactFailed"
)
