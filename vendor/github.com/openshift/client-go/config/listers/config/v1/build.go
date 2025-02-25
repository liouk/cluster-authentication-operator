// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	configv1 "github.com/openshift/api/config/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers"
	cache "k8s.io/client-go/tools/cache"
)

// BuildLister helps list Builds.
// All objects returned here must be treated as read-only.
type BuildLister interface {
	// List lists all Builds in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*configv1.Build, err error)
	// Get retrieves the Build from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*configv1.Build, error)
	BuildListerExpansion
}

// buildLister implements the BuildLister interface.
type buildLister struct {
	listers.ResourceIndexer[*configv1.Build]
}

// NewBuildLister returns a new BuildLister.
func NewBuildLister(indexer cache.Indexer) BuildLister {
	return &buildLister{listers.New[*configv1.Build](indexer, configv1.Resource("build"))}
}
