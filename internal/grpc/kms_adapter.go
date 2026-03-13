package grpc

import (
	"context"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// KMSAdapter bridges the proto KMSServiceServer interface to the internal
// KMSService and KeyService implementations.
type KMSAdapter struct {
	pb.UnimplementedKMSServiceServer
	kmsSvc *service.KMSService
	keySvc *service.KeyService
}

// NewKMSAdapter creates a new KMSAdapter.
func NewKMSAdapter(kmsSvc *service.KMSService, keySvc *service.KeyService) *KMSAdapter {
	return &KMSAdapter{kmsSvc: kmsSvc, keySvc: keySvc}
}

func (a *KMSAdapter) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	resp, err := a.kmsSvc.Encrypt(ctx, &service.EncryptRequest{
		TenantID:  req.TenantId,
		ScopeID:   req.ScopeId,
		Plaintext: req.Plaintext,
		AAD:       req.Aad,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &pb.EncryptResponse{
		Ciphertext:   resp.Ciphertext,
		KeyVersionId: resp.KeyVersionID,
	}, nil
}

func (a *KMSAdapter) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	resp, err := a.kmsSvc.Decrypt(ctx, &service.DecryptRequest{
		TenantID:     req.TenantId,
		ScopeID:      req.ScopeId,
		Ciphertext:   req.Ciphertext,
		AAD:          req.Aad,
		KeyVersionID: req.KeyVersionId,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &pb.DecryptResponse{Plaintext: resp.Plaintext}, nil
}

func (a *KMSAdapter) BatchEncrypt(ctx context.Context, req *pb.BatchEncryptRequest) (*pb.BatchEncryptResponse, error) {
	items := make([]service.BatchEncryptItem, len(req.Items))
	for i, item := range req.Items {
		items[i] = service.BatchEncryptItem{
			Plaintext: item.Plaintext,
			AAD:       item.Aad,
		}
	}
	resp, err := a.kmsSvc.BatchEncrypt(ctx, &service.BatchEncryptRequest{
		TenantID: req.TenantId,
		ScopeID:  req.ScopeId,
		Items:    items,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	pbItems := make([]*pb.EncryptResponse, len(resp.Items))
	for i, item := range resp.Items {
		pbItems[i] = &pb.EncryptResponse{
			Ciphertext:   item.Ciphertext,
			KeyVersionId: item.KeyVersionID,
		}
	}
	return &pb.BatchEncryptResponse{Items: pbItems}, nil
}

func (a *KMSAdapter) BatchDecrypt(ctx context.Context, req *pb.BatchDecryptRequest) (*pb.BatchDecryptResponse, error) {
	items := make([]service.DecryptRequest, len(req.Items))
	for i, item := range req.Items {
		items[i] = service.DecryptRequest{
			TenantID:     req.TenantId,
			ScopeID:      req.ScopeId,
			Ciphertext:   item.Ciphertext,
			AAD:          item.Aad,
			KeyVersionID: item.KeyVersionId,
		}
	}
	resp, err := a.kmsSvc.BatchDecrypt(ctx, &service.BatchDecryptRequest{
		TenantID: req.TenantId,
		ScopeID:  req.ScopeId,
		Items:    items,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	pbItems := make([]*pb.DecryptResponse, len(resp.Items))
	for i, item := range resp.Items {
		pbItems[i] = &pb.DecryptResponse{Plaintext: item.Plaintext}
	}
	return &pb.BatchDecryptResponse{Items: pbItems}, nil
}

func (a *KMSAdapter) CreateDataKey(ctx context.Context, req *pb.CreateDataKeyRequest) (*pb.CreateDataKeyResponse, error) {
	resp, err := a.keySvc.CreateDataKey(ctx, &service.CreateDataKeyRequest{
		TenantID: req.TenantId,
		ScopeID:  req.ScopeId,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &pb.CreateDataKeyResponse{
		KeyVersionId: resp.KeyVersionID,
		Version:      int32(resp.Version),
	}, nil
}

func (a *KMSAdapter) RotateDataKey(ctx context.Context, req *pb.RotateDataKeyRequest) (*pb.RotateDataKeyResponse, error) {
	resp, err := a.keySvc.RotateDataKey(ctx, &service.RotateDataKeyRequest{
		TenantID: req.TenantId,
		ScopeID:  req.ScopeId,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &pb.RotateDataKeyResponse{NewKeyVersionId: resp.NewKeyVersionID}, nil
}

func (a *KMSAdapter) ReEncrypt(context.Context, *pb.ReEncryptRequest) (*pb.ReEncryptResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ReEncrypt not implemented")
}

func (a *KMSAdapter) GetKeyInfo(ctx context.Context, req *pb.GetKeyInfoRequest) (*pb.GetKeyInfoResponse, error) {
	resp, err := a.keySvc.GetKeyInfo(ctx, &service.GetKeyInfoRequest{
		TenantID: req.TenantId,
		ScopeID:  req.ScopeId,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &pb.GetKeyInfoResponse{
		KeyVersionId:    resp.KeyVersionID,
		Version:         int32(resp.Version),
		EncryptionCount: resp.EncryptionCount,
		MaxEncryptions:  resp.MaxEncryptions,
		Status:          resp.Status,
	}, nil
}
