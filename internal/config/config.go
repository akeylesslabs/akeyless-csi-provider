package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/akeylesslabs/akeyless-go/v3"
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
)

type accessType string

const (
	AccessKey         accessType = "access_key"
	AWSIAM            accessType = "aws_iam"
	AzureAD           accessType = "azure_ad"
	GCP               accessType = "gcp"
	UniversalIdentity accessType = "universal_identity"
	K8S               accessType = "k8s"
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
	if config.Parameters.AkeylessAccessType == "" {
		config.Parameters.AkeylessAccessType = string(config.detectAccessType(AklClient))

		if config.Parameters.AkeylessAccessType == "" {
			return Config{}, fmt.Errorf("failed to detect access type of %s", config.AkeylessAccessID)
		}
		log.Printf("successfully connected using %s access type", config.AkeylessAccessType)
	} else {
		// will perform initial authentiaction
		config.detectAccessType(AklClient)
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

	if parameters.AkeylessAccessKey == "" && secret != nil {
		parameters.AkeylessAccessKey = secret["akeylessAccessKey"]
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

	// Set default values.
	if parameters.AkeylessGatewayURL == "" {
		parameters.AkeylessGatewayURL = defaultAkeylessGatewayURL
	}

	if parameters.AkeylessAccessType == "" {
		parameters.AkeylessAccessType = string(AccessKey)
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

func (c *Config) validate() error {
	// Some basic validation checks.
	if c.TargetPath == "" {
		return errors.New("missing target path field")
	}
	if len(c.Parameters.Secrets) == 0 {
		return errors.New("no secrets configured - the provider will not read any secret material")
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

	setAuthToken(c.AkeylessUIDInitToken)

	if err := c.rotateUIDToken(context.Background(), aklClient); err == nil {
		return UniversalIdentity
	}

	return ""
}
