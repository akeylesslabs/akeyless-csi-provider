package provider

import (
	"context"
	"fmt"
	"log"

	"github.com/akeylesslabs/akeyless-csi-provider/internal/config"
	"github.com/akeylesslabs/akeyless-go/v2"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

// provider implements the secrets-store-csi-driver provider interface and communicates with the Akeyless
type provider struct {
	cache map[string]*akeyless.Item
}

func NewProvider() *provider {
	p := &provider{
		cache: make(map[string]*akeyless.Item),
	}
	return p
}

func (p *provider) getSecret(ctx context.Context, body akeyless.DescribeItem) *akeyless.Item {
	if it, ok := p.cache[body.Name]; ok {
		return it
	}

	it, _, err := config.AklClient.DescribeItem(ctx).Body(body).Execute()
	if err != nil {
		log.Fatalf("Failed to get secret %v: %v", body.Name, err.Error())
		return nil
	}
	p.cache[body.Name] = &it
	return &it
}

// MountSecretsStoreObjectContent mounts content of the vault object to target path
func (p *provider) HandleMountRequest(ctx context.Context, cfg config.Config) (*pb.MountResponse, error) {
	versions := make(map[string]string)

	body := akeyless.DescribeItem{}
	if cfg.UsingUID() {
		body.SetUidToken(config.GetAuthToken())
	} else {
		body.SetToken(config.GetAuthToken())
	}

	var files []*pb.File
	for _, secret := range cfg.Parameters.Secrets {
		body.SetName(secret.SecretPath)
		it := p.getSecret(ctx, body)
		if it == nil {
			continue
		}

		versions[fmt.Sprintf("%s:%s", secret.ObjectName, secret.SecretPath)] = "0"

		files = append(files, &pb.File{Path: secret.ObjectName, Mode: int32(cfg.FilePermission), Contents: []byte(it.GetPublicValue())})
		log.Printf("secret added to mount response, directory: %v, file: %v", cfg.TargetPath, secret.ObjectName)
	}

	var ov []*pb.ObjectVersion
	for k, v := range versions {
		ov = append(ov, &pb.ObjectVersion{Id: k, Version: v})
	}

	return &pb.MountResponse{
		ObjectVersion: ov,
		Files:         files,
	}, nil
}
