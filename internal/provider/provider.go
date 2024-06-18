package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/akeylesslabs/akeyless-go/v4"
	"log"
	"strconv"
	"time"

	"github.com/akeylesslabs/akeyless-csi-provider/internal/config"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

var apiErr akeyless.GenericOpenAPIError

// Provider implements the secrets-store-csi-driver Provider interface and communicates with the Akeyless
type cacheEntity struct {
	EntryTime time.Time
	FileName  string
	Value     string
}
type Provider struct {
	cache    map[string]*cacheEntity
	versions map[string]string
}

type Item struct {
	ItemName    string `json:"item_name"`
	ItemType    string `json:"item_type"`
	LastVersion int32  `json:"last_version"`
}

func NewProvider() *Provider {
	p := &Provider{
		cache: make(map[string]*cacheEntity),
	}
	return p
}

func (p *Provider) loadItems(ctx context.Context, cfg config.Config) {

	p.versions = make(map[string]string)

	body := akeyless.GetSecretValue{}
	if cfg.UsingUID() {
		body.SetUidToken(config.GetAuthToken())
	} else {
		body.SetToken(config.GetAuthToken())
	}

	for _, secret := range cfg.Parameters.Secrets {
		version, secVal, err := p.GetSecretByType(ctx, secret.SecretPath, cfg)
		if err != nil {
			log.Fatalf(err.Error())
			return
		}
		p.versions[fmt.Sprintf("%s:%s", secret.FileName, secret.SecretPath)] = strconv.Itoa(int(version))
		ce, ok := p.cache[secret.SecretPath]
		if !ok || ce == nil || time.Now().Sub(ce.EntryTime) > time.Minute*5 {
			p.cache[secret.SecretPath] = &cacheEntity{FileName: secret.FileName}
		}
		p.cache[secret.SecretPath].Value = secVal
		p.cache[secret.SecretPath].EntryTime = time.Now()
	}
}

func (p *Provider) GetSecretByType(ctx context.Context, itemName string, cfg config.Config) (int32, string, error) {
	item, err := p.DescribeItem(ctx, itemName, cfg)
	if err != nil {
		return 0, "", err
	}
	version := item.GetLastVersion()
	secretType := item.GetItemType()

	var secret string
	switch secretType {
	case "STATIC_SECRET":
		secret, err = p.GetStaticSecret(ctx, item.GetItemName(), cfg)
	case "CERTIFICATE":
		secret, err = p.GetCertificate(ctx, item.GetItemName(), cfg)
	case "ROTATED_SECRET":
		secret, err = p.GetRotatedSecret(ctx, item.GetItemName(), cfg)
	default:
		return 0, "", fmt.Errorf("unsupported item type %s for secret %s", secretType, itemName)
	}
	return version, secret, err
}

func (p *Provider) DescribeItem(ctx context.Context, itemName string, cfg config.Config) (*akeyless.Item, error) {
	body := akeyless.DescribeItem{
		Name: itemName,
	}

	if cfg.UsingUID() {
		body.SetUidToken(config.GetAuthToken())
	} else {
		body.SetToken(config.GetAuthToken())
	}

	gsvOut, res, err := config.AklClient.DescribeItem(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			var item *Item
			err = json.Unmarshal(apiErr.Body(), &item)
			if err != nil {
				return nil, fmt.Errorf("can't describe item: %v, error: %v", itemName, string(apiErr.Body()))
			}
		} else {
			return nil, fmt.Errorf("can't describe item: %w", err)
		}
	}
	defer res.Body.Close()

	return &gsvOut, nil
}

func (p *Provider) GetCertificate(ctx context.Context, itemName string, cfg config.Config) (string, error) {
	body := akeyless.GetCertificateValue{
		Name: itemName,
	}

	if cfg.UsingUID() {
		body.SetUidToken(config.GetAuthToken())
	} else {
		body.SetToken(config.GetAuthToken())
	}

	gcvOut, res, err := config.AklClient.GetCertificateValue(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return "", fmt.Errorf("can't get certificate value: %v", string(apiErr.Body()))
		}
		return "", fmt.Errorf("can't get certificate value: %w", err)
	}
	defer res.Body.Close()

	out, err := json.Marshal(gcvOut)
	if err != nil {
		return "", fmt.Errorf("can't marshal certificate value: %w", err)
	}

	return string(out), nil
}

func (p *Provider) GetStaticSecret(ctx context.Context, itemName string, cfg config.Config) (string, error) {
	body := akeyless.GetSecretValue{
		Names: []string{itemName},
	}

	if cfg.UsingUID() {
		body.SetUidToken(config.GetAuthToken())
	} else {
		body.SetToken(config.GetAuthToken())
	}

	gsvOut, res, err := config.AklClient.GetSecretValue(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return "", fmt.Errorf("can't get secret value: %v", string(apiErr.Body()))
		}
		return "", fmt.Errorf("can't get secret value: %w", err)
	}
	defer res.Body.Close()
	val, ok := gsvOut[itemName]
	if !ok {
		return "", fmt.Errorf("can't get secret: %v", itemName)
	}

	return val.(string), nil
}

// HandleMountRequest mounts content of the vault object to target path
func (p *Provider) HandleMountRequest(ctx context.Context, cfg config.Config) (*pb.MountResponse, error) {
	p.loadItems(ctx, cfg)

	var files []*pb.File
	for name, value := range p.cache {
		files = append(files, &pb.File{Path: value.FileName, Mode: int32(cfg.FilePermission), Contents: []byte(value.Value)})
		log.Printf("secret added to mount response, directory: %v, file: %v", cfg.TargetPath, name)
	}

	var ov []*pb.ObjectVersion
	for k, v := range p.versions {
		ov = append(ov, &pb.ObjectVersion{Id: k, Version: v})
	}

	return &pb.MountResponse{
		ObjectVersion: ov,
		Files:         files,
	}, nil
}

func (p *Provider) GetRotatedSecret(ctx context.Context, itemName string, cfg config.Config) (string, error) {
	body := akeyless.GetRotatedSecretValue{
		Names: itemName,
	}
	body.SetJson(true)
	if cfg.UsingUID() {
		body.SetUidToken(config.GetAuthToken())
	} else {
		body.SetToken(config.GetAuthToken())
	}

	gsvOut, res, err := config.AklClient.GetRotatedSecretValue(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return "", fmt.Errorf("can't get secret value: %v", string(apiErr.Body()))
		}
		return "", fmt.Errorf("can't get secret value: %w", err)
	}
	defer res.Body.Close()
	val, ok := gsvOut["value"]
	if !ok {
		return "", fmt.Errorf("can't get secret: %v", itemName)
	}
	jsonValue, err := json.MarshalIndent(val, "", "  ")
	if err != nil {
		return "", fmt.Errorf("can't get secret value: %v", val)
	}

	return string(jsonValue), nil
}
