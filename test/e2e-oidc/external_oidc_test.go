package e2e

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned"
	operatorversionedclient "github.com/openshift/client-go/operator/clientset/versioned"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	test "github.com/openshift/cluster-authentication-operator/test/library"
	"github.com/stretchr/testify/require"
	apiregistrationclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	"k8s.io/utils/ptr"

	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/golang-jwt/jwt/v5"
)

const (
	oidcClientId     = "admin-cli"
	oidcGroupsClaim  = "groups"
	oidcGroupsPrefix = ""

	managedNS = "openshift-config-managed"
	authCM    = "auth-config"
)

func TestExternalOIDCWithKeycloak(t *testing.T) {
	testCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	testClient, err := newTestClient(t)
	require.NoError(t, err)

	checkFeatureGatesOrSkip(t, testCtx, testClient.configClient, features.FeatureGateExternalOIDC, features.FeatureGateExternalOIDCWithAdditionalClaimMappings)

	// post-test cluster cleanup
	var cleanups []func()
	defer test.IDPCleanupWrapper(func() {
		t.Logf("cleaning up after test")
		ts := time.Now()
		for _, c := range cleanups {
			c()
		}
		t.Logf("cleanup completed after %s", time.Now().Sub(ts))
	})()

	origAuthSpec := (*testClient.getAuth(t, testCtx)).Spec.DeepCopy()
	cleanups = append(cleanups, func() {
		kasOriginalRevision := testClient.kasLatestAvailableRevision(t, testCtx)

		err := testClient.authResourceRollback(testCtx, origAuthSpec)
		require.NoError(t, err, "failed to rollback auth resource during cleanup")

		err = test.WaitForNewKASRollout(t, testCtx, testClient.operatorConfigClient.OperatorV1().KubeAPIServers(), kasOriginalRevision)
		require.NoError(t, err, "failed to wait for KAS rollout during cleanup")

		err = wait.PollUntilContextTimeout(testCtx, 30*time.Second, 5*time.Minute, false, func(ctx context.Context) (done bool, err error) {
			return testClient.validateOAuthResources(testCtx, false)
		})
		require.NoError(t, err, "failed to wait for OAuth resources to be present during cleanup")
	})

	// keycloak setup
	var idpName string
	var kcClient *test.KeycloakClient
	kcClient, idpName, c := test.AddKeycloakIDP(t, testClient.kubeConfig, true)
	cleanups = append(cleanups, c...)
	t.Logf("keycloak Admin URL: %s", kcClient.AdminURL())

	// default-ingress-cert is copied to openshift-config and used as the CA for the IdP
	// see test/library/idpdeployment.go:332
	caBundleName := idpName + "-ca"
	idpURL := kcClient.IssuerURL()

	// run tests

	testSpec := authSpecForOIDCProvider(idpName, idpURL, caBundleName, oidcGroupsClaim, oidcClientId)

	typeOAuth := ptr.To(configv1.AuthenticationTypeIntegratedOAuth)
	typeOIDC := ptr.To(configv1.AuthenticationTypeOIDC)
	operatorAvailable := []configv1.ClusterOperatorStatusCondition{
		{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue},
		{Type: configv1.OperatorProgressing, Status: configv1.ConditionFalse},
		{Type: configv1.OperatorDegraded, Status: configv1.ConditionFalse},
		{Type: configv1.OperatorUpgradeable, Status: configv1.ConditionTrue},
	}

	t.Run("auth-config cm must not exist and gets deleted by the CAO if manually created when type not OIDC", func(t *testing.T) {
		testClient.checkPreconditions(t, testCtx, typeOAuth, operatorAvailable, nil)

		_, err := testClient.kubeClient.CoreV1().ConfigMaps(managedNS).Get(testCtx, authCM, metav1.GetOptions{})
		require.True(t, errors.IsNotFound(err), "openshift-config-managed/auth-config configmap must be missing")

		// create cm
		cm := v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      authCM,
				Namespace: managedNS,
			},
			Data: map[string]string{
				"test": "value",
			},
		}
		newCM, err := testClient.kubeClient.CoreV1().ConfigMaps(managedNS).Create(testCtx, &cm, metav1.CreateOptions{})
		require.NoError(t, err)
		require.Equal(t, cm.Data, newCM.Data)

		// wait for CAO to delete it
		wait.PollUntilContextTimeout(testCtx, 2*time.Second, 1*time.Minute, false, func(ctx context.Context) (bool, error) {
			_, err := testClient.kubeClient.CoreV1().ConfigMaps(managedNS).Get(testCtx, authCM, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				return true, nil
			}

			return false, err
		})
	})

	t.Run("invalid OIDC config degrades auth operator", func(t *testing.T) {
		for _, tt := range []struct {
			name                string
			specUpdate          func(*configv1.AuthenticationSpec)
			requireFeatureGates []configv1.FeatureGateName
		}{
			{
				name: "invalid issuer CA bundle",
				specUpdate: func(s *configv1.AuthenticationSpec) {
					s.OIDCProviders[0].Issuer.CertificateAuthority.Name = "invalid-ca-bundle"
				},
				requireFeatureGates: []configv1.FeatureGateName{},
			},
			{
				name: "invalid issuer URL",
				specUpdate: func(s *configv1.AuthenticationSpec) {
					s.OIDCProviders[0].Issuer.URL = "https://invalid-idp.testing"
				},
				requireFeatureGates: []configv1.FeatureGateName{},
			},
			{
				name: "uncompilable CEL expression for uid claim mapping",
				specUpdate: func(s *configv1.AuthenticationSpec) {
					s.OIDCProviders[0].ClaimMappings.UID = &configv1.TokenClaimOrExpressionMapping{
						Expression: "^&*!@#^*(",
					}
				},
				requireFeatureGates: []configv1.FeatureGateName{features.FeatureGateExternalOIDCWithAdditionalClaimMappings},
			},
			{
				name: "uncompilable CEL expression for extras claim mapping",
				specUpdate: func(s *configv1.AuthenticationSpec) {
					s.OIDCProviders[0].ClaimMappings.Extra = []configv1.ExtraMapping{
						{
							Key:             "testing/key",
							ValueExpression: "^&*!@#^*(",
						},
					}
				},
				requireFeatureGates: []configv1.FeatureGateName{features.FeatureGateExternalOIDCWithAdditionalClaimMappings},
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				for _, fg := range tt.requireFeatureGates {
					if !featureGateEnabled(testCtx, testClient.configClient, fg) {
						t.Skipf("skipping as required feature gate %q is not enabled", fg)
					}
				}

				err := testClient.authResourceRollback(testCtx, origAuthSpec)
				require.NoError(t, err, "failed to roll back auth resource")

				testClient.checkPreconditions(t, testCtx, typeOAuth, operatorAvailable, nil)

				testClient.updateAuthResource(t, testCtx, testSpec, tt.specUpdate)

				require.NoError(t, test.WaitForClusterOperatorDegraded(t, testClient.configClient.ConfigV1(), "authentication"))
			})
		}
	})

	t.Run("OIDC config rolls out successfully", func(t *testing.T) {
		err := testClient.authResourceRollback(testCtx, origAuthSpec)
		require.NoError(t, err, "failed to roll back auth resource")

		for _, tt := range []struct {
			claim          string
			prefixPolicy   configv1.UsernamePrefixPolicy
			prefix         *configv1.UsernamePrefix
			expectedPrefix string
		}{
			{"email", configv1.Prefix, &configv1.UsernamePrefix{PrefixString: "oidc-test:"}, "oidc-test:"},
			{"email", configv1.NoPrefix, nil, ""},
			{"sub", configv1.NoOpinion, nil, idpURL + "#"},
			{"email", configv1.NoOpinion, nil, ""},
		} {
			policyStr := "NoOpinion"
			if len(tt.prefixPolicy) > 0 {
				policyStr = string(tt.prefixPolicy)
			}
			testName := fmt.Sprintf("username claim %s prefix policy %s", tt.claim, policyStr)
			t.Run(testName, func(t *testing.T) {
				testClient.checkPreconditions(t, testCtx, nil, operatorAvailable, operatorAvailable)

				kasOriginalRevision := testClient.kasLatestAvailableRevision(t, testCtx)
				auth := testClient.updateAuthResource(t, testCtx, testSpec, func(baseSpec *configv1.AuthenticationSpec) {
					baseSpec.OIDCProviders[0].ClaimMappings.Username = configv1.UsernameClaimMapping{
						Claim:        tt.claim,
						PrefixPolicy: tt.prefixPolicy,
						Prefix:       tt.prefix,
					}
				})

				require.NoError(t, test.WaitForClusterOperatorStatusAlwaysAvailable(t, testCtx, testClient.configClient.ConfigV1(), "authentication"))
				require.NoError(t, test.WaitForClusterOperatorStatusAlwaysAvailable(t, testCtx, testClient.configClient.ConfigV1(), "kube-apiserver"))

				testClient.requireKASRolloutSuccessful(t, testCtx, &auth.Spec, kasOriginalRevision, tt.expectedPrefix)

				testClient.testOIDCAuthentication(t, testCtx, kcClient, tt.claim, tt.expectedPrefix, true)
			})
		}
	})

	t.Run("auth-config cm must exist and gets overwritten by the CAO if manually modified when type OIDC", func(t *testing.T) {
		testClient.checkPreconditions(t, testCtx, typeOIDC, operatorAvailable, nil)

		cm, err := testClient.kubeClient.CoreV1().ConfigMaps(managedNS).Get(testCtx, authCM, metav1.GetOptions{})
		require.NoError(t, err)
		require.NotNil(t, cm)

		orig := cm.DeepCopy()
		cm.Data["auth-config.json"] = "manually overwritten"
		cm, err = testClient.kubeClient.CoreV1().ConfigMaps(managedNS).Update(testCtx, cm, metav1.UpdateOptions{})
		require.NoError(t, err)
		require.NotEqual(t, cm.Data, orig.Data)

		// wait for CAO to overwrite it
		wait.PollUntilContextTimeout(testCtx, 2*time.Second, 1*time.Minute, false, func(ctx context.Context) (bool, error) {
			cm, err := testClient.kubeClient.CoreV1().ConfigMaps(managedNS).Get(testCtx, authCM, metav1.GetOptions{})
			if err != nil {
				return false, err
			}

			return equality.Semantic.DeepEqual(cm.Data, orig.Data), nil
		})
	})

	t.Run("OIDC config rolls out successfully but breaks authentication when username claim is unknown", func(t *testing.T) {
		testClient.checkPreconditions(t, testCtx, nil, operatorAvailable, operatorAvailable)

		kasOriginalRevision := testClient.kasLatestAvailableRevision(t, testCtx)
		auth := testClient.updateAuthResource(t, testCtx, testSpec, func(baseSpec *configv1.AuthenticationSpec) {
			baseSpec.OIDCProviders[0].ClaimMappings.Username = configv1.UsernameClaimMapping{
				Claim:        "unknown",
				PrefixPolicy: configv1.NoPrefix,
				Prefix:       nil,
			}
		})

		require.NoError(t, test.WaitForClusterOperatorStatusAlwaysAvailable(t, testCtx, testClient.configClient.ConfigV1(), "authentication"))
		require.NoError(t, test.WaitForClusterOperatorStatusAlwaysAvailable(t, testCtx, testClient.configClient.ConfigV1(), "kube-apiserver"))

		testClient.requireKASRolloutSuccessful(t, testCtx, &auth.Spec, kasOriginalRevision, "")

		testClient.testOIDCAuthentication(t, testCtx, kcClient, "", "", false)
	})
}

type oidcAuthResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	IdToken          string `json:"id_token"`
	NotBeforePolicy  int    `json:"not_before_policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

type expectedClaims struct {
	jwt.RegisteredClaims
	Email             string `json:"email"`
	Type              string `json:"typ"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	PreferredUsername string `json:"preferred_username"`
}

type jwks struct {
	Keys []struct {
		KID string `json:"kid"`
		Use string `json:"use"`
		KTY string `json:"kty"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func fetchIssuerJWKS(issuerURL string) (*jwks, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// grab openid-configuration JSON which contains the URL of the provider's JWKS
	resp, err := client.Get(issuerURL + "/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("could not get issuer OpenID well-known configuration: %v", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not parse well-known response body: %v", err)
	}

	var oidcConfig struct {
		JwksURL string `json:"jwks_uri"`
	}

	if err := json.Unmarshal(respBytes, &oidcConfig); err != nil {
		return nil, fmt.Errorf("could not unmarshal OpenID config: %v", err)
	}

	// grab the provider's JWKS which contains the pubkey to verify token signatures
	resp, err = client.Get(oidcConfig.JwksURL)
	if err != nil {
		return nil, fmt.Errorf("could not get issuer OpenID well-known JWKS configuration: %v", err)
	}
	defer resp.Body.Close()

	respBytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not parse well-known JWKS response body: %v", err)
	}

	var issuerJWKS jwks
	if err := json.Unmarshal(respBytes, &issuerJWKS); err != nil {
		return nil, fmt.Errorf("could not unmarshal JWKS: %v", err)
	}

	return &issuerJWKS, nil
}

func extractRSAPubKeyFunc(issuerJWKS *jwks) func(*jwt.Token) (any, error) {
	return func(token *jwt.Token) (any, error) {
		for _, key := range issuerJWKS.Keys {
			if key.KID == token.Header["kid"] {
				switch key.Alg {
				case "RS256":
					n, err := base64.RawURLEncoding.DecodeString(key.N)
					if err != nil {
						return nil, fmt.Errorf("could not decode N: %v", err)
					}
					e, err := base64.RawURLEncoding.DecodeString(key.E)
					if err != nil {
						return nil, fmt.Errorf("could not decode E: %v", err)
					}

					pubkey := &rsa.PublicKey{
						N: new(big.Int).SetBytes(n),
						E: int(new(big.Int).SetBytes(e).Int64()),
					}

					return pubkey, nil
				}

				return nil, fmt.Errorf("unexpected signing algorithm for key '%s': %s", key.KID, key.Alg)
			}
		}

		return nil, fmt.Errorf("could not find an RSA key for signing use in the provided JWKS")
	}
}

func checkFeatureGatesOrSkip(t *testing.T, ctx context.Context, configClient *configclient.Clientset, features ...configv1.FeatureGateName) {
	featureGates, err := configClient.ConfigV1().FeatureGates().Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(t, err)

	if len(featureGates.Status.FeatureGates) != 1 {
		// fail test if there are multiple feature gate versions (i.e. ongoing upgrade)
		t.Fatalf("multiple feature gate versions detected")
		return
	}

	atLeastOneFeatureEnabled := false
	for _, feature := range features {
		for _, gate := range featureGates.Status.FeatureGates[0].Enabled {
			if gate.Name == feature {
				atLeastOneFeatureEnabled = true
				break
			}
		}

		if atLeastOneFeatureEnabled {
			break
		}
	}

	if !atLeastOneFeatureEnabled {
		t.Skipf("skipping as none of the feature gates in %v are enabled", features)
	}
}

func authSpecForOIDCProvider(idpName, idpURL, caBundleName, groupsClaim string, oidcClientID configv1.TokenAudience) *configv1.AuthenticationSpec {
	spec := configv1.AuthenticationSpec{
		Type:                      configv1.AuthenticationTypeOIDC,
		WebhookTokenAuthenticator: nil,
		OIDCProviders: []configv1.OIDCProvider{
			{
				Name: idpName,
				Issuer: configv1.TokenIssuer{
					URL:       idpURL,
					Audiences: []configv1.TokenAudience{oidcClientID},
					CertificateAuthority: configv1.ConfigMapNameReference{
						Name: caBundleName,
					},
				},
				ClaimMappings: configv1.TokenClaimMappings{
					Username: configv1.UsernameClaimMapping{
						Claim:        "email",
						PrefixPolicy: configv1.Prefix,
						Prefix: &configv1.UsernamePrefix{
							PrefixString: "oidc-test:",
						},
					},
					Groups: configv1.PrefixedClaimMapping{
						TokenClaimMapping: configv1.TokenClaimMapping{
							Claim: groupsClaim,
						},
					},
				},
			},
		},
	}

	return &spec
}

type testClient struct {
	kubeConfig            *rest.Config
	kubeClient            *kubernetes.Clientset
	configClient          *configclient.Clientset
	operatorConfigClient  *operatorversionedclient.Clientset
	oauthClient           oauthclient.Interface
	routeClient           routeclient.Interface
	apiregistrationClient apiregistrationclient.Interface
}

func newTestClient(t *testing.T) (*testClient, error) {
	tc := &testClient{
		kubeConfig: test.NewClientConfigForTest(t),
	}

	var err error
	tc.kubeClient, err = kubernetes.NewForConfig(tc.kubeConfig)
	if err != nil {
		return nil, err
	}

	tc.configClient, err = configclient.NewForConfig(tc.kubeConfig)
	if err != nil {
		return nil, err
	}

	tc.operatorConfigClient, err = operatorversionedclient.NewForConfig(tc.kubeConfig)
	if err != nil {
		return nil, err
	}

	tc.oauthClient, err = oauthclient.NewForConfig(tc.kubeConfig)
	if err != nil {
		return nil, err
	}

	tc.routeClient, err = routeclient.NewForConfig(tc.kubeConfig)
	if err != nil {
		return nil, err
	}

	tc.apiregistrationClient, err = apiregistrationclient.NewForConfig(tc.kubeConfig)
	if err != nil {
		return nil, err
	}

	return tc, nil
}

func (tc *testClient) getAuth(t *testing.T, ctx context.Context) *configv1.Authentication {
	auth, err := tc.configClient.ConfigV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(t, err, "failed to get authentication/cluster")
	require.NotNil(t, auth)

	return auth
}

// updateAuthResource deep-copies the baseSpec, applies updates to the copy and persists them in the auth resource
func (tc *testClient) updateAuthResource(t *testing.T, ctx context.Context, baseSpec *configv1.AuthenticationSpec, updateAuthSpec func(baseSpec *configv1.AuthenticationSpec)) *configv1.Authentication {
	auth := tc.getAuth(t, ctx)
	if updateAuthSpec == nil {
		return auth
	}

	spec := baseSpec.DeepCopy()
	updateAuthSpec(spec)

	auth.Spec = *spec
	auth, err := tc.configClient.ConfigV1().Authentications().Update(ctx, auth, metav1.UpdateOptions{})
	require.NoError(t, err, "failed to update authentication/cluster")
	require.True(t, equality.Semantic.DeepEqual(auth.Spec, *spec))

	return auth
}

func (tc *testClient) checkPreconditions(t *testing.T, ctx context.Context, authType *configv1.AuthenticationType, caoStatus []configv1.ClusterOperatorStatusCondition, kasoStatus []configv1.ClusterOperatorStatusCondition) {
	err := wait.PollUntilContextTimeout(ctx, 30*time.Second, 20*time.Minute, false, func(ctx context.Context) (bool, error) {
		if authType != nil {
			expected := *authType
			if len(expected) == 0 {
				expected = configv1.AuthenticationTypeIntegratedOAuth
			}

			auth := tc.getAuth(t, ctx)
			actual := auth.Spec.Type
			if len(actual) == 0 {
				actual = configv1.AuthenticationTypeIntegratedOAuth
			}

			if expected != actual {
				t.Logf("unexpected auth type; test requires '%s', but got '%s'", expected, actual)
				return false, nil
			}
		}

		if len(caoStatus) > 0 {
			ok, conditions, err := test.CheckClusterOperatorStatus(t, ctx, tc.configClient.ConfigV1(), "authentication", caoStatus...)
			if err != nil {
				return false, fmt.Errorf("could not determine authentication operator status: %v", err)
			} else if !ok {
				t.Logf("unexpected authentication operator status: %v", conditions)
				return false, nil
			}
		}

		if len(kasoStatus) > 0 {
			ok, conditions, err := test.CheckClusterOperatorStatus(t, ctx, tc.configClient.ConfigV1(), "kube-apiserver", kasoStatus...)
			if err != nil {
				return false, fmt.Errorf("could not determine kube-apiserver operator status: %v", err)
			} else if !ok {
				t.Logf("unexpected kube-apiserver operator status: %v", conditions)
				return false, nil
			}
		}

		return true, nil
	})

	require.NoError(t, err, "test preconditions failed: %v", err)
}

func (tc *testClient) kasLatestAvailableRevision(t *testing.T, ctx context.Context) int32 {
	kas, err := tc.operatorConfigClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(t, err, "failed to get kubeapiserver/cluster")
	return kas.Status.LatestAvailableRevision
}

func (tc *testClient) validateKASConfig(t *testing.T, ctx context.Context) int32 {
	kas, err := tc.operatorConfigClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(t, err)

	var observedConfig map[string]any
	err = json.Unmarshal(kas.Spec.ObservedConfig.Raw, &observedConfig)
	require.NoError(t, err)

	apiServerArguments := observedConfig["apiServerArguments"].(map[string]any)

	require.Nil(t, apiServerArguments["authentication-token-webhook-config-file"])
	require.Nil(t, apiServerArguments["authentication-token-webhook-version"])
	require.Nil(t, observedConfig["authConfig"])

	authConfigArg := apiServerArguments["authentication-config"].([]any)
	require.NotEmpty(t, authConfigArg)
	require.Equal(t, authConfigArg[0].(string), "/etc/kubernetes/static-pod-resources/configmaps/auth-config/auth-config.json")

	return kas.Status.LatestAvailableRevision
}

func (tc *testClient) validateAuthConfigJSON(t *testing.T, ctx context.Context, authSpec *configv1.AuthenticationSpec, usernamePrefix, groupsClaim, groupsPrefix string, kasRevision int32) {
	idpURL := authSpec.OIDCProviders[0].Issuer.URL
	caBundleName := authSpec.OIDCProviders[0].Issuer.CertificateAuthority.Name
	certData := ""
	if len(caBundleName) > 0 {
		cm, err := tc.kubeClient.CoreV1().ConfigMaps("openshift-config").Get(ctx, caBundleName, metav1.GetOptions{})
		require.NoError(t, err)
		certData = cm.Data["ca-bundle.crt"]
	}

	authConfigJSONTemplate := `{"kind":"AuthenticationConfiguration","apiVersion":"apiserver.config.k8s.io/v1beta1","jwt":[{"issuer":{"url":"%s","certificateAuthority":"%s","audiences":[%s],"audienceMatchPolicy":"MatchAny"},"claimMappings":{"username":{"claim":"%s","prefix":"%s"},"groups":{"claim":"%s","prefix":"%s"},"uid":{}}}]}`
	// If the ExternalOIDCWithUIDAndExtraClaimMappings feature gate is enabled, default the uid claim to "sub"
	if featureGateEnabled(ctx, tc.configClient, features.FeatureGateExternalOIDCWithAdditionalClaimMappings) {
		authConfigJSONTemplate = `{"kind":"AuthenticationConfiguration","apiVersion":"apiserver.config.k8s.io/v1beta1","jwt":[{"issuer":{"url":"%s","certificateAuthority":"%s","audiences":[%s],"audienceMatchPolicy":"MatchAny"},"claimMappings":{"username":{"claim":"%s","prefix":"%s"},"groups":{"claim":"%s","prefix":"%s"},"uid":{"claim":"sub"}}}]}`
	}

	expectedAuthConfigJSON := fmt.Sprintf(authConfigJSONTemplate,
		idpURL,
		strings.ReplaceAll(certData, "\n", "\\n"),
		strings.Join([]string{fmt.Sprintf(`"%s"`, oidcClientId)}, ","),
		authSpec.OIDCProviders[0].ClaimMappings.Username.Claim,
		usernamePrefix,
		groupsClaim,
		groupsPrefix,
	)

	for _, cm := range []struct {
		ns   string
		name string
	}{
		{"openshift-config-managed", "auth-config"},
		{"openshift-kube-apiserver", "auth-config"},
		{"openshift-kube-apiserver", fmt.Sprintf("auth-config-%d", kasRevision)},
	} {
		actualCM, err := tc.kubeClient.CoreV1().ConfigMaps(cm.ns).Get(ctx, cm.name, metav1.GetOptions{})
		require.NoError(t, err)
		require.Equal(t, expectedAuthConfigJSON, actualCM.Data["auth-config.json"], "unexpected auth-config.json contents in %s/%s", actualCM.Namespace, actualCM.Name)
	}
}

func (tc *testClient) validateOAuthResources(ctx context.Context, requireMissing bool) (bool, error) {
	dynamicClient, err := dynamic.NewForConfig(tc.kubeConfig)
	if err != nil {
		return false, fmt.Errorf("unexpected error while creating dynamic client: %v", err)
	}

	for _, obj := range []struct {
		gvr       schema.GroupVersionResource
		namespace string
		name      string
	}{
		{schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, "openshift-authentication", "oauth-openshift"},
		{schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, "openshift-oauth-apiserver", "apiserver"},
		{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}, "openshift-authentication", "v4-0-config-system-metadata"},
		{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}, "openshift-authentication", "v4-0-config-system-trusted-ca-bundle"},
		{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}, "openshift-authentication", "v4-0-config-system-service-ca"},
		{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}, "openshift-authentication", "v4-0-config-system-cliconfig"},
		{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}, "openshift-authentication", "v4-0-config-system-ocp-branding-template"},
		{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}, "openshift-authentication", "v4-0-config-system-session"},
		{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}, "openshift-authentication", "oauth-openshift"},
		{schema.GroupVersionResource{Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices"}, "", "v1.oauth.openshift.io"},
		{schema.GroupVersionResource{Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices"}, "", "v1.user.openshift.io"},
		{schema.GroupVersionResource{Group: "oauth.openshift.io", Version: "v1", Resource: "oauthclients"}, "", "openshift-browser-client"},
		{schema.GroupVersionResource{Group: "oauth.openshift.io", Version: "v1", Resource: "oauthclients"}, "", "openshift-challenging-client"},
		{schema.GroupVersionResource{Group: "oauth.openshift.io", Version: "v1", Resource: "oauthclients"}, "", "openshift-cli-client"},
	} {
		_, err := dynamicClient.Resource(obj.gvr).Namespace(obj.namespace).Get(ctx, obj.name, metav1.GetOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return false, fmt.Errorf("unexpected error while getting resource %s/%s: %v", obj.namespace, obj.name, err)
		} else if requireMissing != errors.IsNotFound(err) {
			return false, fmt.Errorf("resource %s/%s wanted missing: %v; got: %v", obj.namespace, obj.name, requireMissing, !errors.IsNotFound((err)))
		}
	}

	// routes
	for _, obj := range []struct{ namespace, name string }{
		{"openshift-authentication", "oauth-openshift"},
	} {
		_, err := tc.routeClient.RouteV1().Routes(obj.namespace).Get(ctx, obj.name, metav1.GetOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return false, fmt.Errorf("unexpected error while getting route %s/%s: %v", obj.namespace, obj.name, err)
		} else if requireMissing != errors.IsNotFound(err) {
			return false, fmt.Errorf("route %s/%s wanted missing: %v; got: %v", obj.namespace, obj.name, requireMissing, !errors.IsNotFound((err)))
		}

		// ingress status
		ingress, err := tc.configClient.ConfigV1().Ingresses().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		found := false
		for _, route := range ingress.Status.ComponentRoutes {
			if route.Name == obj.name && route.Namespace == obj.namespace {
				found = true
				break
			}
		}

		if !requireMissing && !found {
			return false, fmt.Errorf("route %s required but was not found", obj)
		} else if requireMissing && found {
			return false, fmt.Errorf("route %s required to be missing but was found", obj)
		}
	}

	return true, nil
}

func (tc *testClient) testOIDCAuthentication(t *testing.T, ctx context.Context, kcClient *test.KeycloakClient, usernameClaim, usernamePrefix string, expectAuthSuccess bool) {
	// re-authenticate to ensure we always have a fresh token
	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		err := kcClient.AuthenticatePassword(oidcClientId, "", "admin", "password")
		return err == nil, err
	})
	require.NoError(t, err)

	group := names.SimpleNameGenerator.GenerateName("e2e-keycloak-group-")
	err = kcClient.CreateGroup(group)
	require.NoError(t, err)

	user := names.SimpleNameGenerator.GenerateName("e2e-keycloak-user-")
	email := fmt.Sprintf("%s@test.dev", user)
	password := "password"
	firstName := "Homer"
	lastName := "Simpson"
	err = kcClient.CreateUser(
		user,
		email,
		password,
		[]string{group},
		map[string]string{
			"firstName": firstName,
			"lastName":  lastName,
		},
	)
	require.NoError(t, err)

	// use a keycloak client for the user created above to fetch its tokens
	transport, err := rest.TransportFor(tc.kubeConfig)
	require.NoError(t, err)
	userClient := test.KeycloakClientFor(t, transport, kcClient.IssuerURL(), "master")
	err = userClient.AuthenticatePassword(oidcClientId, "", user, password)
	require.NoError(t, err)
	accessTokenStr, idTokenStr := userClient.Tokens()
	require.NotEmpty(t, accessTokenStr, "access token must not be empty")
	require.NotEmpty(t, idTokenStr, "id token must not be empty")

	// fetch issuer's JWKS and use it to parse JWT tokens
	issuerJWKS, err := fetchIssuerJWKS(kcClient.IssuerURL())
	require.NoError(t, err)
	require.NotNil(t, issuerJWKS)
	keyfunc := extractRSAPubKeyFunc(issuerJWKS)

	accessToken, err := jwt.ParseWithClaims(accessTokenStr, &expectedClaims{}, keyfunc)
	require.NoError(t, err)
	require.NotNil(t, accessToken)

	idToken, err := jwt.ParseWithClaims(idTokenStr, &expectedClaims{}, keyfunc)
	require.NoError(t, err)
	require.NotNil(t, idToken)

	// validate the contents of the OIDC tokens
	actualAccessTokenClaims := accessToken.Claims.(*expectedClaims)
	require.True(t, accessToken.Valid)
	require.Equal(t, userClient.IssuerURL(), actualAccessTokenClaims.Issuer)
	require.Equal(t, user, actualAccessTokenClaims.PreferredUsername)
	require.Equal(t, email, actualAccessTokenClaims.Email)
	require.Equal(t, "Bearer", actualAccessTokenClaims.Type)
	require.Equal(t, firstName, actualAccessTokenClaims.GivenName)
	require.Equal(t, lastName, actualAccessTokenClaims.FamilyName)
	require.Equal(t, fmt.Sprintf("%s %s", firstName, lastName), actualAccessTokenClaims.Name)
	require.NotEmpty(t, actualAccessTokenClaims.Subject)

	actualIDTokenClaims := idToken.Claims.(*expectedClaims)
	require.True(t, idToken.Valid)
	require.Equal(t, userClient.IssuerURL(), actualIDTokenClaims.Issuer)
	require.Equal(t, user, actualIDTokenClaims.PreferredUsername)
	require.Equal(t, email, actualIDTokenClaims.Email)
	require.Equal(t, "ID", actualIDTokenClaims.Type)
	require.Equal(t, jwt.ClaimStrings{oidcClientId}, actualIDTokenClaims.Audience)
	require.Equal(t, firstName, actualIDTokenClaims.GivenName)
	require.Equal(t, lastName, actualIDTokenClaims.FamilyName)
	require.Equal(t, fmt.Sprintf("%s %s", firstName, lastName), actualIDTokenClaims.Name)
	require.NotEmpty(t, actualIDTokenClaims.Subject)

	// test authentication via the kube-apiserver
	// create a new kube client that uses the OIDC id_token as a bearer token
	kubeConfig := rest.AnonymousClientConfig(tc.kubeConfig)
	kubeConfig.BearerToken = idTokenStr
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	require.NoError(t, err)

	ssr, err := kubeClient.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if expectAuthSuccess {
		// test authentication with the OIDC token using a self subject review
		expectedUsername := ""
		switch usernameClaim {
		case "email":
			expectedUsername = usernamePrefix + email
		case "sub":
			expectedUsername = usernamePrefix + actualIDTokenClaims.Subject
		default:
			t.Fatalf("unexpected username claim: %s", usernameClaim)
		}

		require.NoError(t, err)
		require.NotNil(t, ssr)
		require.Contains(t, ssr.Status.UserInfo.Groups, "system:authenticated")
		require.Equal(t, expectedUsername, ssr.Status.UserInfo.Username)
	} else {
		require.Error(t, err)
		require.True(t, errors.IsUnauthorized(err))
	}
}

func (tc *testClient) requireKASRolloutSuccessful(t *testing.T, testCtx context.Context, authSpec *configv1.AuthenticationSpec, kasOriginalRevision int32, expectedUsernamePrefix string) {
	// wait for KAS rollout
	err := test.WaitForNewKASRollout(t, testCtx, tc.operatorConfigClient.OperatorV1().KubeAPIServers(), kasOriginalRevision)
	require.NoError(t, err, "failed to wait for KAS rollout")

	kasRevision := tc.validateKASConfig(t, testCtx)
	tc.validateAuthConfigJSON(t, testCtx, authSpec, expectedUsernamePrefix, oidcGroupsClaim, oidcGroupsPrefix, kasRevision)
}

func (tc *testClient) authResourceRollback(ctx context.Context, origAuthSpec *configv1.AuthenticationSpec) error {
	auth, err := tc.configClient.ConfigV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("rollback failed for authentication '%s' while retrieving fresh object: %v", auth.Name, err)
	}

	if !equality.Semantic.DeepEqual(auth.Spec, *origAuthSpec) {
		auth.Spec = *origAuthSpec
		if _, err := tc.configClient.ConfigV1().Authentications().Update(ctx, auth, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("rollback failed for authentication '%s' while updating object: %v", auth.Name, err)
		}
	}

	return nil
}

func featureGateEnabled(ctx context.Context, configClient *configclient.Clientset, feature configv1.FeatureGateName) bool {
	featureGates, err := configClient.ConfigV1().FeatureGates().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return false
	}

	if len(featureGates.Status.FeatureGates) == 0 {
		return false
	}

	for _, enabled := range featureGates.Status.FeatureGates[0].Enabled {
		if enabled.Name == feature {
			return true
		}
	}

	return false
}
