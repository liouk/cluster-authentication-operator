// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	"context"

	v1 "github.com/openshift/api/authorization/v1"
	authorizationv1 "github.com/openshift/client-go/authorization/applyconfigurations/authorization/v1"
	scheme "github.com/openshift/client-go/authorization/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// RoleBindingsGetter has a method to return a RoleBindingInterface.
// A group's client should implement this interface.
type RoleBindingsGetter interface {
	RoleBindings(namespace string) RoleBindingInterface
}

// RoleBindingInterface has methods to work with RoleBinding resources.
type RoleBindingInterface interface {
	Create(ctx context.Context, roleBinding *v1.RoleBinding, opts metav1.CreateOptions) (*v1.RoleBinding, error)
	Update(ctx context.Context, roleBinding *v1.RoleBinding, opts metav1.UpdateOptions) (*v1.RoleBinding, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.RoleBinding, error)
	List(ctx context.Context, opts metav1.ListOptions) (*v1.RoleBindingList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.RoleBinding, err error)
	Apply(ctx context.Context, roleBinding *authorizationv1.RoleBindingApplyConfiguration, opts metav1.ApplyOptions) (result *v1.RoleBinding, err error)
	RoleBindingExpansion
}

// roleBindings implements RoleBindingInterface
type roleBindings struct {
	*gentype.ClientWithListAndApply[*v1.RoleBinding, *v1.RoleBindingList, *authorizationv1.RoleBindingApplyConfiguration]
}

// newRoleBindings returns a RoleBindings
func newRoleBindings(c *AuthorizationV1Client, namespace string) *roleBindings {
	return &roleBindings{
		gentype.NewClientWithListAndApply[*v1.RoleBinding, *v1.RoleBindingList, *authorizationv1.RoleBindingApplyConfiguration](
			"rolebindings",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *v1.RoleBinding { return &v1.RoleBinding{} },
			func() *v1.RoleBindingList { return &v1.RoleBindingList{} }),
	}
}