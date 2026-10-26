package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/akeylesslabs/akeyless-go/v4"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/types"
)

const (
	AkeylessURL               = "AKEYLESS_URL"
	AkeylessAccessType        = "AKEYLESS_ACCESS_TYPE"
	AkeylessAccessID          = "AKEYLESS_ACCESS_ID"
	AkeylessAccessKey         = "AKEYLESS_ACCESS_KEY"
	Credentials               = "CREDENTIALS"
	AkeylessAzureObjectID     = "AKEYLESS_AZURE_OBJECT_ID"
	AkeylessGCPAudience       = "AKEYLESS_GCP_AUDIENCE"
	AkeylessUIDInitToken      = "AKEYLESS_UID_INIT_TOKEN"
	AkeylessK8sAuthConfigName = "AKEYLESS_K8S_AUTH_CONFIG_NAME"
	// AkeylessJWT is an optional bearer JWT for access-type jwt/oauth2.
	// Prefer the provider ServiceAccount token file over a static JWT.
	AkeylessJWT = "AKEYLESS_JWT"
)

type accessType string

const (
	AccessKey         accessType = "access_key"
	AWSIAM            accessType = "aws_iam"
	AzureAD           accessType = "azure_ad"
	GCP               accessType = "gcp"
	UniversalIdentity accessType = "universal_identity"
	K8S               accessType = "k8s"
	// JWT is Akeyless OAuth2.0/JWT auth (API access-type=jwt).
	JWT accessType = "jwt"
	// OAuth2 is accepted as an alias of JWT for SecretProviderClass/env convenience.
	OAuth2 accessType = "oauth2"
)

var (
	AklClient *akeyless.V2ApiService
)

// Config represents all of the provider's configurable behaviour from the MountRequest proto message:
// * Parameters from the `Attributes` field.
// * Plus the rest of the proto fields we consume.
// See sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1/service.pb.go
type Config struct {
	Parameters
	TargetPath     string
	FilePermission os.FileMode
}

// Parameters stores the parameters specified in a mount request's `Attributes` field.
// It consists of the parameters section from the SecretProviderClass being mounted
// and pod metadata provided by the driver.
//
// Top-level values that aren't strings are not directly deserialisable because
// they are defined as literal string types:
// https://github.com/kubernetes-sigs/secrets-store-csi-driver/blob/0ba9810d41cc2dc336c68251d45ebac19f2e7f28/apis/v1alpha1/secretproviderclass_types.go#L59
//
// So we just deserialize by hand to avoid complexity and two passes.
type Parameters struct {
	AkeylessGatewayURL       string
	VaultKubernetesMountPath string
	Secrets                  []Secret
	PodInfo                  PodInfo

	AkeylessAccessType        string
	AkeylessAccessID          string
	AkeylessAccessKey         string
	AkeylessAzureObjectID     string
	AkeylessGCPAudience       string
	AkeylessUIDInitToken      string
	AkeylessK8sAuthConfigName string
	// AkeylessJWT holds a bearer JWT for oauth2/jwt auth when supplied via the
	// CSI driver secrets payload (captured at mount). Live env AKEYLESS_JWT is
	// re-read on each auth. Never read from SPC parameters (etcd).
	AkeylessJWT string

	// accessTypeExplicit is true when akeylessAccessType came from SPC params
	// or AKEYLESS_ACCESS_TYPE (not the access_key default).
	accessTypeExplicit bool
}

type TLSConfig struct {
	CACertPath     string
	CADirectory    string
	TLSServerName  string
	SkipVerify     bool
	ClientCertPath string
	ClientKeyPath  string
}

type PodInfo struct {
	Name               string
	UID                types.UID
	Namespace          string
	ServiceAccountName string
}

type Secret struct {
	FileName   string                 `yaml:"fileName,omitempty"`
	SecretPath string                 `yaml:"secretPath,omitempty"`
	SecretType string                 `yaml:"secretType,omitempty"` // Deprecated, will be ignored
	SecretArgs map[string]interface{} `yaml:"secretArgs,omitempty"`
}

func Parse(secretStr, parametersStr, targetPath, permissionStr string, defaultVaultAddr string, defaultVaultKubernetesMountPath string) (Config, error) {
	config := Config{
		TargetPath: targetPath,
	}

	var err error
	config.Parameters, err = parseParameters(secretStr, parametersStr, defaultVaultAddr, defaultVaultKubernetesMountPath)
	if err != nil {
		return Config{}, err
	}

	AklClient = createClient(config.AkeylessGatewayURL)
	// Skip when AccessID is unset so offline unit tests and incomplete configs
	// can still parse; Mount will fail later without a token.
	if config.AkeylessAccessID != "" {
		if config.accessTypeExplicit {
			// Explicit type: authenticate only with that method (no probing).
			if err := config.authenticateConfigured(context.Background(), AklClient); err != nil {
				return Config{}, err
			}
		} else {
			// Omitted akeylessAccessType: preserve legacy auto-detect so AWS/Azure/GCP/k8s
			// configs without an access key keep working.
			detected := config.detectAccessType(AklClient)
			if detected == "" {
				return Config{}, fmt.Errorf("failed to detect access type of %s", config.AkeylessAccessID)
			}
			config.AkeylessAccessType = string(detected)
		}
		log.Printf("successfully authenticated using %s access type", config.AkeylessAccessType)
	}

	err = json.Unmarshal([]byte(permissionStr), &config.FilePermission)
	if err != nil {
		return Config{}, err
	}

	err = config.validate()
	if err != nil {
		return Config{}, err
	}

	return config, nil
}

func parseParameters(secretStr, parametersStr string, defaultAkeylessGatewayURL string, defaultVaultKubernetesMountPath string) (Parameters, error) {
	var params map[string]string
	err := json.Unmarshal([]byte(parametersStr), &params)
	if err != nil {
		return Parameters{}, err
	}

	var secret map[string]string
	if secretStr != "" {
		err = json.Unmarshal([]byte(secretStr), &secret)
		if err != nil {
			return Parameters{}, err
		}
	}

	var parameters Parameters
	parameters.AkeylessGatewayURL = params["akeylessGatewayURL"]
	parameters.VaultKubernetesMountPath = params["vaultKubernetesMountPath"]
	parameters.PodInfo.Name = params["csi.storage.k8s.io/pod.name"]
	parameters.PodInfo.UID = types.UID(params["csi.storage.k8s.io/pod.uid"])
	parameters.PodInfo.Namespace = params["csi.storage.k8s.io/pod.namespace"]
	parameters.PodInfo.ServiceAccountName = params["csi.storage.k8s.io/serviceAccount.name"]
	parameters.AkeylessAccessType = params["akeylessAccessType"]
	parameters.AkeylessAccessID = params["akeylessAccessID"]
	parameters.AkeylessAccessKey = params["akeylessAccessKey"]
	parameters.AkeylessAzureObjectID = params["akeylessAzureObjectID"]
	parameters.AkeylessGCPAudience = params["akeylessGCPAudience"]
	parameters.AkeylessUIDInitToken = params["akeylessUIDInitToken"]
	parameters.AkeylessK8sAuthConfigName = params["akeylessK8sAuthConfigName"]
	// Intentionally do not accept akeylessJWT from SPC parameters (attrs are
	// often stored in etcd). Prefer SA token file, CSI secrets, or env.

	if parameters.AkeylessAccessKey == "" && secret != nil {
		parameters.AkeylessAccessKey = secret["akeylessAccessKey"]
	}
	if secret != nil {
		parameters.AkeylessJWT = secret["akeylessJWT"]
	}

	secretsYaml := params["objects"]
	if secretsYaml != "" {
		err = yaml.Unmarshal([]byte(secretsYaml), &parameters.Secrets)
		if err != nil {
			return Parameters{}, err
		}
	}

	if parameters.AkeylessGatewayURL == "" {
		parameters.AkeylessGatewayURL = os.Getenv(AkeylessURL)
	}

	if parameters.AkeylessAccessType == "" {
		parameters.AkeylessAccessType = os.Getenv(AkeylessAccessType)
	}
	accessTypeExplicit := parameters.AkeylessAccessType != ""

	if parameters.AkeylessAccessID == "" {
		parameters.AkeylessAccessID = os.Getenv(AkeylessAccessID)
	}

	if parameters.AkeylessAccessKey == "" {
		parameters.AkeylessAccessKey = os.Getenv(AkeylessAccessKey)
	}

	if parameters.AkeylessAccessKey == "" {
		parameters.AkeylessAccessKey = os.Getenv(Credentials)
	}

	if parameters.AkeylessAzureObjectID == "" {
		parameters.AkeylessAzureObjectID = os.Getenv(AkeylessAzureObjectID)
	}

	if parameters.AkeylessGCPAudience == "" {
		parameters.AkeylessGCPAudience = os.Getenv(AkeylessGCPAudience)
	}

	if parameters.AkeylessUIDInitToken == "" {
		parameters.AkeylessUIDInitToken = os.Getenv(AkeylessUIDInitToken)
	}

	if parameters.AkeylessK8sAuthConfigName == "" {
		parameters.AkeylessK8sAuthConfigName = os.Getenv(AkeylessK8sAuthConfigName)
	}

	if parameters.AkeylessJWT == "" {
		parameters.AkeylessJWT = os.Getenv(AkeylessJWT)
	}

	// Set default values.
	if parameters.AkeylessGatewayURL == "" {
		parameters.AkeylessGatewayURL = defaultAkeylessGatewayURL
	}

	if parameters.AkeylessAccessType == "" {
		parameters.AkeylessAccessType = string(AccessKey)
	}
	parameters.accessTypeExplicit = accessTypeExplicit

	if isJWTAccessType(parameters.AkeylessAccessType) {
		// Normalize oauth2 alias to the API access-type value.
		parameters.AkeylessAccessType = string(JWT)
	}

	if parameters.VaultKubernetesMountPath == "" {
		parameters.VaultKubernetesMountPath = defaultVaultKubernetesMountPath
	}

	return parameters, nil
}

func (c *Config) UsingAccessKey() bool {
	return accessType(c.AkeylessAccessType) == AccessKey
}

func (c *Config) UsingAWS() bool {
	return accessType(c.AkeylessAccessType) == AWSIAM
}

func (c *Config) UsingAzure() bool {
	return accessType(c.AkeylessAccessType) == AzureAD
}

func (c *Config) UsingGCP() bool {
	return accessType(c.AkeylessAccessType) == GCP
}

func (c *Config) UsingUID() bool {
	return accessType(c.AkeylessAccessType) == UniversalIdentity
}

func (c *Config) UsingK8S() bool {
	return accessType(c.AkeylessAccessType) == K8S
}

func (c *Config) UsingJWT() bool {
	return isJWTAccessType(c.AkeylessAccessType)
}

func isJWTAccessType(accType string) bool {
	switch accessType(accType) {
	case JWT, OAuth2:
		return true
	default:
		return false
	}
}

func (c *Config) validate() error {
	// Some basic validation checks.
	if c.TargetPath == "" {
		return errors.New("missing target path field")
	}
	if len(c.Parameters.Secrets) == 0 {
		return errors.New("no secrets configured - the provider will not read any secret material")
	}
	if c.UsingJWT() && c.AkeylessAccessID == "" {
		return errors.New("akeylessAccessID is required for jwt/oauth2 authentication")
	}

	return nil
}

func createClient(akeylessGatewayURL string) *akeyless.V2ApiService {
	cfg := &akeyless.Configuration{
		Servers: []akeyless.ServerConfiguration{
			{
				URL: akeylessGatewayURL,
			},
		},
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   55 * time.Second,
					KeepAlive: 55 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   30 * time.Second,
				ExpectContinueTimeout: 30 * time.Second,
				// the total limit is bounded per host (MaxIdleConnsPerHost)
				// MaxIdleConns: 0,
				MaxIdleConnsPerHost: 100,
				MaxConnsPerHost:     200,
			},
			Timeout: 55 * time.Second,
		},
	}
	return akeyless.NewAPIClient(cfg).V2Api
}

// authenticateConfigured performs the initial auth for the explicitly configured
// access type. Unlike detectAccessType it does not probe other methods, which
// avoids accidentally authenticating with a weaker or unintended credential.
func (c *Config) authenticateConfigured(ctx context.Context, aklClient *akeyless.V2ApiService) error {
	switch {
	case c.UsingAccessKey():
		return c.authWithAccessKey(ctx, aklClient)
	case c.UsingAWS():
		return c.authWithAWS(ctx, aklClient)
	case c.UsingAzure():
		return c.authWithAzure(ctx, aklClient)
	case c.UsingGCP():
		return c.authWithGCP(ctx, aklClient)
	case c.UsingK8S():
		return c.authWithK8S(ctx, aklClient)
	case c.UsingJWT():
		return c.authWithJWT(ctx, aklClient)
	case c.UsingUID():
		setAuthToken(c.AkeylessUIDInitToken)
		return c.rotateUIDToken(ctx, aklClient)
	default:
		return fmt.Errorf("unsupported akeylessAccessType %q", c.AkeylessAccessType)
	}
}

func (c *Config) detectAccessType(aklClient *akeyless.V2ApiService) accessType {
	if c.AkeylessAccessID == "" {
		return ""
	}

	log.Printf("trying to detect privileged credentials for %v", c.AkeylessAccessID)

	if err := c.authWithAccessKey(context.Background(), aklClient); err == nil {
		return AccessKey
	}

	if err := c.authWithAWS(context.Background(), aklClient); err == nil {
		return AWSIAM
	}

	if err := c.authWithAzure(context.Background(), aklClient); err == nil {
		return AzureAD
	}

	if err := c.authWithGCP(context.Background(), aklClient); err == nil {
		return GCP
	}

	if err := c.authWithK8S(context.Background(), aklClient); err == nil {
		return K8S
	}

	if err := c.authWithJWT(context.Background(), aklClient); err == nil {
		return JWT
	}

	setAuthToken(c.AkeylessUIDInitToken)

	if err := c.rotateUIDToken(context.Background(), aklClient); err == nil {
		return UniversalIdentity
	}

	return ""
}
