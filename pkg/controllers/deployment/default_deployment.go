package deployment

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ghodss/yaml"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"

	"github.com/openshift/cluster-authentication-operator/bindata"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common/arguments"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
	observeoauth "github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/oauth"
	"github.com/openshift/cluster-authentication-operator/pkg/operator/datasync"
)

func getOAuthServerDeployment(
	operatorSpec *operatorv1.OperatorSpec,
	proxyConfig *configv1.Proxy,
	bootstrapUserExists bool,
	resourceVersions ...string,
) (*appsv1.Deployment, error) {
	// load deployment
	deployment := resourceread.ReadDeploymentV1OrDie(bindata.MustAsset("oauth-openshift/deployment.yaml"))

	// force redeploy when any associated resource changes
	// we use a hash to prevent this value from growing indefinitely
	// need to sort first in order to get a stable array
	sort.Strings(resourceVersions)
	rvs := strings.Join(resourceVersions, ",")
	klog.V(4).Infof("tracked resource versions: %s", rvs)
	rvsHash := sha512.Sum512([]byte(rvs))
	rvsHashStr := base64.RawURLEncoding.EncodeToString(rvsHash[:])
	if deployment.Annotations == nil {
		deployment.Annotations = map[string]string{}
	}
	deployment.Annotations["operator.openshift.io/rvs-hash"] = rvsHashStr

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations["operator.openshift.io/rvs-hash"] = rvsHashStr

	// Ensure a rollout when the bootstrap user goes away
	if bootstrapUserExists {
		deployment.Spec.Template.Annotations["operator.openshift.io/bootstrap-user-exists"] = "true"
	}

	templateSpec := &deployment.Spec.Template.Spec
	container := &templateSpec.Containers[0]

	// image spec
	if container.Image == "${IMAGE}" {
		container.Image = os.Getenv("IMAGE_OAUTH_SERVER")
	}

	// set proxy env vars
	container.Env = append(container.Env, proxyConfigToEnvVars(proxyConfig)...)

	// set log level
	container.Args[0] = strings.Replace(container.Args[0], "${LOG_LEVEL}", fmt.Sprintf("%d", getLogLevel(operatorSpec.LogLevel)), -1)

	observedConfig, err := common.UnstructuredConfigFrom(
		operatorSpec.ObservedConfig.Raw,
		configobservation.OAuthServerConfigPrefix,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to read the operatorconfig prefix %q: %w",
			configobservation.OAuthServerConfigPrefix,
			err,
		)
	}

	idpSyncData, err := getSyncDataFromOperatorConfig(observedConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to get IDP sync data: %v", err)
	}

	// mount more secrets and config maps
	v, m, err := idpSyncData.ToVolumesAndMounts()
	if err != nil {
		return nil, fmt.Errorf("unable to transform observed IDP sync data to volumes and mounts: %v", err)
	}
	templateSpec.Volumes = append(templateSpec.Volumes, v...)
	container.VolumeMounts = append(container.VolumeMounts, m...)

	argsRaw, err := getOAuthServerArgumentsRaw(observedConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve server arguments from observed config: %w", err)
	}

	args, err := arguments.Parse(argsRaw)
	if err != nil {
		return nil, fmt.Errorf("unable to parse raw server arguments: %w", err)
	}

	container.Args[0] = strings.Replace(
		container.Args[0],
		"${SERVER_ARGUMENTS}",
		arguments.Encode(args),
		1,
	)

	return deployment, nil
}

func getSyncDataFromOperatorConfig(observedConfig []byte) (*datasync.ConfigSyncData, error) {
	var configDeserialized map[string]interface{}
	if err := yaml.Unmarshal(observedConfig, &configDeserialized); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the observedConfig: %v", err)
	}

	return observeoauth.GetIDPConfigSyncData(configDeserialized)
}

// TODO: reuse the library-go helper for this
func getLogLevel(logLevel operatorv1.LogLevel) int {
	switch logLevel {
	case operatorv1.Normal, "": // treat empty string to mean the default
		return 2
	case operatorv1.Debug:
		return 4
	case operatorv1.Trace:
		return 6
	case operatorv1.TraceAll:
		return 100 // this is supposed to be 8 but I prefer "all" to really mean all
	default:
		return 0
	}
}

// TODO: move to library-go:w
func proxyConfigToEnvVars(proxy *configv1.Proxy) []corev1.EnvVar {
	var envVars []corev1.EnvVar
	envVars = appendEnvVar(envVars, "NO_PROXY", proxy.Status.NoProxy)
	envVars = appendEnvVar(envVars, "HTTP_PROXY", proxy.Status.HTTPProxy)
	envVars = appendEnvVar(envVars, "HTTPS_PROXY", proxy.Status.HTTPSProxy)
	return envVars
}

func appendEnvVar(envVars []corev1.EnvVar, envName, envVal string) []corev1.EnvVar {
	if len(envVal) > 0 {
		return append(envVars, corev1.EnvVar{Name: envName, Value: envVal})
	}
	return envVars
}

func getOAuthServerArgumentsRaw(observedConfig []byte) (map[string]interface{}, error) {
	configDeserialized := new(struct {
		Args map[string]interface{} `json:"serverArguments"`
	})
	if err := json.Unmarshal(observedConfig, &configDeserialized); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the observedConfig: %v", err)
	}

	return configDeserialized.Args, nil
}
