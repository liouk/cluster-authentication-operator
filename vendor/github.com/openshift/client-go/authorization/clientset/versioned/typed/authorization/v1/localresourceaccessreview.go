// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	"context"

	v1 "github.com/openshift/api/authorization/v1"
	scheme "github.com/openshift/client-go/authorization/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gentype "k8s.io/client-go/gentype"
)

// LocalResourceAccessReviewsGetter has a method to return a LocalResourceAccessReviewInterface.
// A group's client should implement this interface.
type LocalResourceAccessReviewsGetter interface {
	LocalResourceAccessReviews(namespace string) LocalResourceAccessReviewInterface
}

// LocalResourceAccessReviewInterface has methods to work with LocalResourceAccessReview resources.
type LocalResourceAccessReviewInterface interface {
	Create(ctx context.Context, localResourceAccessReview *v1.LocalResourceAccessReview, opts metav1.CreateOptions) (*v1.ResourceAccessReviewResponse, error)

	LocalResourceAccessReviewExpansion
}

// localResourceAccessReviews implements LocalResourceAccessReviewInterface
type localResourceAccessReviews struct {
	*gentype.Client[*v1.LocalResourceAccessReview]
}

// newLocalResourceAccessReviews returns a LocalResourceAccessReviews
func newLocalResourceAccessReviews(c *AuthorizationV1Client, namespace string) *localResourceAccessReviews {
	return &localResourceAccessReviews{
		gentype.NewClient[*v1.LocalResourceAccessReview](
			"localresourceaccessreviews",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *v1.LocalResourceAccessReview { return &v1.LocalResourceAccessReview{} }),
	}
}

// Create takes the representation of a localResourceAccessReview and creates it.  Returns the server's representation of the resourceAccessReviewResponse, and an error, if there is any.
func (c *localResourceAccessReviews) Create(ctx context.Context, localResourceAccessReview *v1.LocalResourceAccessReview, opts metav1.CreateOptions) (result *v1.ResourceAccessReviewResponse, err error) {
	result = &v1.ResourceAccessReviewResponse{}
	err = c.GetClient().Post().
		Namespace(c.GetNamespace()).
		Resource("localresourceaccessreviews").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(localResourceAccessReview).
		Do(ctx).
		Into(result)
	return
}