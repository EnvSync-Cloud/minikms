package grpc

import (
	"context"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// VaultAdapter bridges the proto VaultServiceServer interface to the internal VaultService.
type VaultAdapter struct {
	pb.UnimplementedVaultServiceServer
	vaultSvc *service.VaultService
}

// NewVaultAdapter creates a new VaultAdapter.
func NewVaultAdapter(vaultSvc *service.VaultService) *VaultAdapter {
	return &VaultAdapter{vaultSvc: vaultSvc}
}

// extractSessionToken gets the session token from gRPC metadata.
func extractSessionToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing metadata")
	}

	authValues := md.Get("authorization")
	if len(authValues) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	token := authValues[0]
	// Strip "Bearer " prefix if present
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	return token, nil
}

func (a *VaultAdapter) Write(ctx context.Context, req *pb.VaultWriteRequest) (*pb.VaultWriteResponse, error) {
	token, err := extractSessionToken(ctx)
	if err != nil {
		return nil, err
	}

	var envTypeID *string
	if req.EnvTypeId != "" {
		envTypeID = &req.EnvTypeId
	}

	resp, err := a.vaultSvc.Write(ctx, token, &service.VaultWriteRequest{
		OrgID:     req.OrgId,
		ScopeID:   req.ScopeId,
		EntryType: req.EntryType,
		Key:       req.Key,
		EnvTypeID: envTypeID,
		Value:     req.Value,
		CreatedBy: req.CreatedBy,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	return &pb.VaultWriteResponse{
		Id:           resp.ID,
		Version:      int32(resp.Version),
		KeyVersionId: resp.KeyVersionID,
	}, nil
}

func (a *VaultAdapter) Read(ctx context.Context, req *pb.VaultReadRequest) (*pb.VaultReadResponse, error) {
	token, err := extractSessionToken(ctx)
	if err != nil {
		return nil, err
	}

	var envTypeID *string
	if req.EnvTypeId != "" {
		envTypeID = &req.EnvTypeId
	}

	resp, err := a.vaultSvc.Read(ctx, token, &service.VaultReadRequest{
		OrgID:             req.OrgId,
		ScopeID:           req.ScopeId,
		EntryType:         req.EntryType,
		Key:               req.Key,
		EnvTypeID:         envTypeID,
		ClientSideDecrypt: req.ClientSideDecrypt,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	return vaultReadResponseToProto(resp), nil
}

func (a *VaultAdapter) ReadVersion(ctx context.Context, req *pb.VaultReadVersionRequest) (*pb.VaultReadResponse, error) {
	token, err := extractSessionToken(ctx)
	if err != nil {
		return nil, err
	}

	var envTypeID *string
	if req.EnvTypeId != "" {
		envTypeID = &req.EnvTypeId
	}

	resp, err := a.vaultSvc.ReadVersion(ctx, token, &service.VaultReadVersionRequest{
		OrgID:             req.OrgId,
		ScopeID:           req.ScopeId,
		EntryType:         req.EntryType,
		Key:               req.Key,
		EnvTypeID:         envTypeID,
		Version:           int(req.Version),
		ClientSideDecrypt: req.ClientSideDecrypt,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	return vaultReadResponseToProto(resp), nil
}

func (a *VaultAdapter) Delete(ctx context.Context, req *pb.VaultDeleteRequest) (*pb.VaultDeleteResponse, error) {
	token, err := extractSessionToken(ctx)
	if err != nil {
		return nil, err
	}

	var envTypeID *string
	if req.EnvTypeId != "" {
		envTypeID = &req.EnvTypeId
	}

	err = a.vaultSvc.Delete(ctx, token, &service.VaultDeleteRequest{
		OrgID:     req.OrgId,
		ScopeID:   req.ScopeId,
		EntryType: req.EntryType,
		Key:       req.Key,
		EnvTypeID: envTypeID,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	return &pb.VaultDeleteResponse{Success: true}, nil
}

func (a *VaultAdapter) Destroy(ctx context.Context, req *pb.VaultDestroyRequest) (*pb.VaultDestroyResponse, error) {
	token, err := extractSessionToken(ctx)
	if err != nil {
		return nil, err
	}

	var envTypeID *string
	if req.EnvTypeId != "" {
		envTypeID = &req.EnvTypeId
	}

	count, err := a.vaultSvc.Destroy(ctx, token, &service.VaultDestroyRequest{
		OrgID:     req.OrgId,
		ScopeID:   req.ScopeId,
		EntryType: req.EntryType,
		Key:       req.Key,
		EnvTypeID: envTypeID,
		Version:   int(req.Version),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	return &pb.VaultDestroyResponse{
		Success:        true,
		DestroyedCount: int32(count),
	}, nil
}

func (a *VaultAdapter) List(ctx context.Context, req *pb.VaultListRequest) (*pb.VaultListResponse, error) {
	token, err := extractSessionToken(ctx)
	if err != nil {
		return nil, err
	}

	var envTypeID *string
	if req.EnvTypeId != "" {
		envTypeID = &req.EnvTypeId
	}

	resp, err := a.vaultSvc.List(ctx, token, &service.VaultListRequest{
		OrgID:     req.OrgId,
		ScopeID:   req.ScopeId,
		EntryType: req.EntryType,
		EnvTypeID: envTypeID,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	entries := make([]*pb.VaultListEntry, len(resp.Entries))
	for i, e := range resp.Entries {
		entries[i] = &pb.VaultListEntry{
			Key:           e.Key,
			LatestVersion: int32(e.LatestVersion),
			CreatedAt:     timestamppb.New(e.CreatedAt),
			UpdatedAt:     timestamppb.New(e.UpdatedAt),
		}
	}

	return &pb.VaultListResponse{Entries: entries}, nil
}

func (a *VaultAdapter) History(ctx context.Context, req *pb.VaultHistoryRequest) (*pb.VaultHistoryResponse, error) {
	token, err := extractSessionToken(ctx)
	if err != nil {
		return nil, err
	}

	var envTypeID *string
	if req.EnvTypeId != "" {
		envTypeID = &req.EnvTypeId
	}

	resp, err := a.vaultSvc.History(ctx, token, &service.VaultHistoryRequest{
		OrgID:     req.OrgId,
		ScopeID:   req.ScopeId,
		EntryType: req.EntryType,
		Key:       req.Key,
		EnvTypeID: envTypeID,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	versions := make([]*pb.VaultVersionEntry, len(resp.Versions))
	for i, v := range resp.Versions {
		var createdBy string
		if v.CreatedBy != nil {
			createdBy = *v.CreatedBy
		}
		versions[i] = &pb.VaultVersionEntry{
			Version:      int32(v.Version),
			KeyVersionId: v.KeyVersionID,
			CreatedAt:    timestamppb.New(v.CreatedAt),
			CreatedBy:    createdBy,
			Deleted:      v.Deleted,
			Destroyed:    v.Destroyed,
		}
	}

	return &pb.VaultHistoryResponse{Versions: versions}, nil
}

// vaultReadResponseToProto converts internal VaultReadResponse to protobuf.
func vaultReadResponseToProto(resp *service.VaultReadResponse) *pb.VaultReadResponse {
	pbResp := &pb.VaultReadResponse{
		Id:             resp.ID,
		OrgId:          resp.OrgID,
		ScopeId:        resp.ScopeID,
		EntryType:      resp.EntryType,
		Key:            resp.Key,
		EncryptedValue: resp.EncryptedValue,
		KeyVersionId:   resp.KeyVersionID,
		Version:        int32(resp.Version),
		CreatedAt:      timestamppb.New(resp.CreatedAt),
	}

	if resp.EnvTypeID != nil {
		pbResp.EnvTypeId = *resp.EnvTypeID
	}
	if resp.CreatedBy != nil {
		pbResp.CreatedBy = *resp.CreatedBy
	}

	// BYOK client-side decrypt fields
	pbResp.MemberWrapEphemeralPub = resp.MemberWrapEphemeralPub
	pbResp.MemberWrappedOrgcaKey = resp.MemberWrappedOrgCAKey

	return pbResp
}
