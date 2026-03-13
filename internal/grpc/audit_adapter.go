package grpc

import (
	"context"
	"time"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuditAdapter bridges the proto AuditServiceServer interface to the internal
// AuditService implementation.
type AuditAdapter struct {
	pb.UnimplementedAuditServiceServer
	auditSvc *service.AuditService
}

// NewAuditAdapter creates a new AuditAdapter.
func NewAuditAdapter(auditSvc *service.AuditService) *AuditAdapter {
	return &AuditAdapter{auditSvc: auditSvc}
}

func (a *AuditAdapter) GetAuditLogs(ctx context.Context, req *pb.GetAuditLogsRequest) (*pb.GetAuditLogsResponse, error) {
	resp, err := a.auditSvc.GetAuditLogs(ctx, &service.GetAuditLogsRequest{
		OrgID:  req.OrgId,
		Limit:  int(req.Limit),
		Offset: int(req.Offset),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	entries := make([]*pb.AuditEntry, len(resp.Entries))
	for i, e := range resp.Entries {
		entries[i] = &pb.AuditEntry{
			Id:             e.ID,
			PreviousHash:   e.PreviousHash,
			EntryHash:      e.EntryHash,
			Timestamp:      e.Timestamp.Format(time.RFC3339Nano),
			Action:         e.Action,
			ActorId:        e.ActorID,
			OrgId:          e.OrgID,
			Details:        e.Details,
			RequestJwtHash: e.RequestJWTHash,
		}
	}
	return &pb.GetAuditLogsResponse{Entries: entries}, nil
}

func (a *AuditAdapter) VerifyChain(ctx context.Context, req *pb.VerifyChainRequest) (*pb.VerifyChainResponse, error) {
	resp, err := a.auditSvc.VerifyChain(ctx, &service.VerifyChainRequest{
		OrgID: req.OrgId,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &pb.VerifyChainResponse{Valid: resp.Valid}, nil
}

// compile-time assertion
var _ pb.AuditServiceServer = (*AuditAdapter)(nil)
