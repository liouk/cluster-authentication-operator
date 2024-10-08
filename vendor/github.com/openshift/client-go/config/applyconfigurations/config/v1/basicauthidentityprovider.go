// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

// BasicAuthIdentityProviderApplyConfiguration represents a declarative configuration of the BasicAuthIdentityProvider type for use
// with apply.
type BasicAuthIdentityProviderApplyConfiguration struct {
	OAuthRemoteConnectionInfoApplyConfiguration `json:",inline"`
}

// BasicAuthIdentityProviderApplyConfiguration constructs a declarative configuration of the BasicAuthIdentityProvider type for use with
// apply.
func BasicAuthIdentityProvider() *BasicAuthIdentityProviderApplyConfiguration {
	return &BasicAuthIdentityProviderApplyConfiguration{}
}

// WithURL sets the URL field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the URL field is set to the value of the last call.
func (b *BasicAuthIdentityProviderApplyConfiguration) WithURL(value string) *BasicAuthIdentityProviderApplyConfiguration {
	b.URL = &value
	return b
}

// WithCA sets the CA field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CA field is set to the value of the last call.
func (b *BasicAuthIdentityProviderApplyConfiguration) WithCA(value *ConfigMapNameReferenceApplyConfiguration) *BasicAuthIdentityProviderApplyConfiguration {
	b.CA = value
	return b
}

// WithTLSClientCert sets the TLSClientCert field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TLSClientCert field is set to the value of the last call.
func (b *BasicAuthIdentityProviderApplyConfiguration) WithTLSClientCert(value *SecretNameReferenceApplyConfiguration) *BasicAuthIdentityProviderApplyConfiguration {
	b.TLSClientCert = value
	return b
}

// WithTLSClientKey sets the TLSClientKey field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TLSClientKey field is set to the value of the last call.
func (b *BasicAuthIdentityProviderApplyConfiguration) WithTLSClientKey(value *SecretNameReferenceApplyConfiguration) *BasicAuthIdentityProviderApplyConfiguration {
	b.TLSClientKey = value
	return b
}
