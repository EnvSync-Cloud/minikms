package grpc

import (
	"context"

	pb "github.com/envsync/minikms/api/proto/minikms/v1"
	"github.com/envsync/minikms/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SessionAdapter bridges the proto SessionServiceServer interface to the internal SessionService.
type SessionAdapter struct {
	pb.UnimplementedSessionServiceServer
	sessionSvc *service.SessionService
}

// NewSessionAdapter creates a new SessionAdapter.
func NewSessionAdapter(sessionSvc *service.SessionService) *SessionAdapter {
	return &SessionAdapter{sessionSvc: sessionSvc}
}

func (a *SessionAdapter) CreateSession(ctx context.Context, req *pb.CreateSessionRequest) (*pb.CreateSessionResponse, error) {
	var resp *service.CreateSessionResponse
	var err error

	switch auth := req.Auth.(type) {
	case *pb.CreateSessionRequest_CertAuth:
		resp, err = a.sessionSvc.CreateSessionByCert(ctx, &service.CreateSessionByCertRequest{
			CertPEM:     auth.CertAuth.CertPem,
			SignedNonce: auth.CertAuth.SignedNonce,
			Nonce:       auth.CertAuth.Nonce,
			Scopes:      req.Scopes,
		})
	case *pb.CreateSessionRequest_ManagedAuth:
		resp, err = a.sessionSvc.CreateSessionManaged(ctx, &service.CreateSessionManagedRequest{
			MemberID:   auth.ManagedAuth.MemberId,
			OrgID:      auth.ManagedAuth.OrgId,
			CertSerial: auth.ManagedAuth.CertSerial,
			Scopes:     req.Scopes,
		})
	default:
		return nil, status.Error(codes.InvalidArgument, "auth method required")
	}

	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "%v", err)
	}

	return &pb.CreateSessionResponse{
		SessionToken: resp.SessionToken,
		ExpiresAt:    timestamppb.New(resp.ExpiresAt),
		Scopes:       resp.Scopes,
	}, nil
}

func (a *SessionAdapter) ValidateSession(ctx context.Context, req *pb.ValidateSessionRequest) (*pb.ValidateSessionResponse, error) {
	resp, err := a.sessionSvc.ValidateSession(ctx, &service.ValidateSessionRequest{
		SessionToken: req.SessionToken,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	pbResp := &pb.ValidateSessionResponse{
		Valid:      resp.Valid,
		MemberId:  resp.MemberID,
		OrgId:     resp.OrgID,
		Role:      resp.Role,
		CertSerial: resp.CertSerial,
		Scopes:    resp.Scopes,
	}
	if resp.Valid {
		pbResp.ExpiresAt = timestamppb.New(resp.ExpiresAt)
	}

	return pbResp, nil
}

func (a *SessionAdapter) RevokeSession(ctx context.Context, req *pb.RevokeSessionRequest) (*pb.RevokeSessionResponse, error) {
	err := a.sessionSvc.RevokeSession(ctx, req.SessionToken)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	return &pb.RevokeSessionResponse{Success: true}, nil
}

func (a *SessionAdapter) RevokeMemberSessions(ctx context.Context, req *pb.RevokeMemberSessionsRequest) (*pb.RevokeMemberSessionsResponse, error) {
	count, err := a.sessionSvc.RevokeMemberSessions(ctx, req.MemberId, req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	return &pb.RevokeMemberSessionsResponse{RevokedCount: int32(count)}, nil
}

func (a *SessionAdapter) ListSessions(ctx context.Context, req *pb.ListSessionsRequest) (*pb.ListSessionsResponse, error) {
	resp, err := a.sessionSvc.ListSessions(ctx, req.MemberId, req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	sessions := make([]*pb.SessionInfo, len(resp.Sessions))
	for i, s := range resp.Sessions {
		sessions[i] = &pb.SessionInfo{
			Jti:        s.JTI,
			CertSerial: s.CertSerial,
			Scopes:     s.Scopes,
			IssuedAt:   timestamppb.New(s.IssuedAt),
			ExpiresAt:  timestamppb.New(s.ExpiresAt),
			Revoked:    s.Revoked,
		}
	}

	return &pb.ListSessionsResponse{Sessions: sessions}, nil
}
