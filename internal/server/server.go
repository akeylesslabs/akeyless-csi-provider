package server

import (
	"context"
	"fmt"
	"log"

	"github.com/akeylesslabs/akeyless-csi-provider/internal/config"
	"github.com/akeylesslabs/akeyless-csi-provider/internal/provider"
	"github.com/akeylesslabs/akeyless-csi-provider/internal/version"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

var (
	_ pb.CSIDriverProviderServer = (*Server)(nil)
)

// Server implements the secrets-store-csi-driver provider gRPC service interface.
type Server struct {
	VaultAddr  string
	VaultMount string
}

func (p *Server) Version(context.Context, *pb.VersionRequest) (*pb.VersionResponse, error) {
	return &pb.VersionResponse{
		Version:        "v1alpha1",
		RuntimeName:    "akeyless-csi-provider",
		RuntimeVersion: version.BuildVersion,
	}, nil
}

func (p *Server) Mount(ctx context.Context, req *pb.MountRequest) (*pb.MountResponse, error) {
	cfg, err := config.Parse(req.GetSecrets(), req.Attributes, req.TargetPath, req.Permission, p.VaultAddr, p.VaultMount)
	if err != nil {
		return nil, err
	}

	log.Printf("starting authentication routine to %v", cfg.AkeylessGatewayURL)
	closed := make(chan bool, 1)
	err = cfg.StartAuthentication(ctx, closed)

	if err != nil {
		log.Printf("failed to start authentication routine, error: %v", err)
		return nil, err
	}

	provider := provider.NewProvider()
	resp, err := provider.HandleMountRequest(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("error making mount request: %w", err)
	}

	return resp, nil
}
