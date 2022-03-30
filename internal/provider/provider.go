package provider

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/akeylesslabs/akeyless-csi-provider/internal/config"
	"github.com/akeylesslabs/akeyless-go/v2"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

// provider implements the secrets-store-csi-driver provider interface and communicates with the Akeyless
type cacheEntity struct {
	EntryTime time.Time
	FileName  string
	Value     string
}
type provider struct {
	cache map[string]*cacheEntity
}

func NewProvider() *provider {
	p := &provider{
		cache: make(map[string]*cacheEntity),
	}
	return p
}

func (p *provider) loadSecrets(ctx context.Context, body akeyless.GetSecretValue) {
	secrets, _, err := config.AklClient.GetSecretValue(ctx).Body(body).Execute()
	if err != nil {
		log.Fatalf("Failed to get secret %v: %v", body.Names[0], err.Error())
		return
	}

	for k, v := range secrets {
		p.cache[k].Value = v
		p.cache[k].EntryTime = time.Now()
	}
}

// MountSecretsStoreObjectContent mounts content of the vault object to target path
func (p *provider) HandleMountRequest(ctx context.Context, cfg config.Config) (*pb.MountResponse, error) {
	versions := make(map[string]string)

	body := akeyless.GetSecretValue{}
	if cfg.UsingUID() {
		body.SetUidToken(config.GetAuthToken())
	} else {
		body.SetToken(config.GetAuthToken())
	}

	var files []*pb.File
	var names []string
	for _, secret := range cfg.Parameters.Secrets {
		versions[fmt.Sprintf("%s:%s", secret.FileName, secret.SecretPath)] = "0"
		ce, ok := p.cache[secret.SecretPath]
		if !ok || ce == nil || time.Now().Sub(ce.EntryTime) > time.Minute*5 {
			names = append(names, secret.SecretPath)
			p.cache[secret.SecretPath] = &cacheEntity{FileName: secret.FileName}
		}
	}
	body.SetNames(names)
	p.loadSecrets(ctx, body)

	for name, value := range p.cache {
		files = append(files, &pb.File{Path: value.FileName, Mode: int32(cfg.FilePermission), Contents: []byte(value.Value)})
		log.Printf("secret added to mount response, directory: %v, file: %v", cfg.TargetPath, name)
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
