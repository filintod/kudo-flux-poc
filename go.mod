module github.com/kudobuilder/kudoflux

go 1.15

require (
	github.com/cyphar/filepath-securejoin v0.2.2
	github.com/fluxcd/pkg/apis/meta v0.9.0
	github.com/fluxcd/pkg/runtime v0.11.0
	github.com/fluxcd/pkg/untar v0.0.5
	github.com/fluxcd/source-controller/api v0.4.1
	github.com/go-logr/logr v0.4.0
	github.com/hashicorp/go-retryablehttp v0.6.8
	github.com/kudobuilder/kudo v0.19.0
	github.com/onsi/ginkgo v1.15.0
	github.com/onsi/gomega v1.10.5
	github.com/spf13/afero v1.4.0
	github.com/spf13/pflag v1.0.5
	k8s.io/api v0.20.4
	k8s.io/apiextensions-apiserver v0.20.2
	k8s.io/apimachinery v0.20.4
	k8s.io/client-go v0.20.4
	sigs.k8s.io/cli-utils v0.25.0
	sigs.k8s.io/controller-runtime v0.8.3
)

replace github.com/kudobuilder/kudo => /Users/fduran/proj/kudo
