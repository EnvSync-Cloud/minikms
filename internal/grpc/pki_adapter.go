package grpc

import (
	"context"
	"encoding/pem"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PKIAdapter bridges the proto PKIServiceServer interface to the internal
// PKIService. Durable CA material is loaded by the service for every request,
// allowing calls to move freely between replicas.
type PKIAdapter struct {
	pb.UnimplementedPKIServiceServer
	pkiSvc *service.PKIService
}

// NewPKIAdapter creates a new PKIAdapter.
func NewPKIAdapter(pkiSvc *service.PKIService) *PKIAdapter {
	return &PKIAdapter{pkiSvc: pkiSvc}
}

func (a *PKIAdapter) CreateOrgCA(ctx context.Context, req *pb.CreateOrgCARequest) (*pb.CreateOrgCAResponse, error) {
	resp, _, _, err := a.pkiSvc.CreateOrgCAFull(ctx, &service.CreateOrgCARequest{
		OrgID:   req.OrgId,
		OrgName: req.OrgName,
	})
	if err != nil {
		return nil, toStatusError(err)
	}

	return &pb.CreateOrgCAResponse{
		CertPem:   resp.CertPEM,
		SerialHex: resp.SerialHex,
	}, nil
}

func (a *PKIAdapter) IssueMemberCert(ctx context.Context, req *pb.IssueMemberCertRequest) (*pb.IssueMemberCertResponse, error) {
	orgCACert, orgCAKey, err := a.pkiSvc.LoadOrgCA(ctx, req.OrgId)
	if err != nil {
		return nil, toStatusError(err)
	}

	resp, err := a.pkiSvc.IssueMemberCert(ctx, &service.IssueMemberCertRequest{
		MemberID:    req.MemberId,
		MemberEmail: req.MemberEmail,
		OrgID:       req.OrgId,
		Role:        req.Role,
		OrgCACert:   orgCACert,
		OrgCAKey:    orgCAKey,
	})
	if err != nil {
		return nil, toStatusError(err)
	}

	// Create Org CA wrap for the new member so they can decrypt vault entries
	memberPub, err := keys.ParseMemberCertPublicKey(resp.CertPEM)
	if err == nil {
		_ = a.pkiSvc.WrapOrgCAForMember(ctx, req.OrgId, req.MemberId, resp.SerialHex, memberPub, orgCAKey)
	}

	return &pb.IssueMemberCertResponse{
		CertPem:   resp.CertPEM,
		KeyPem:    resp.KeyPEM,
		SerialHex: resp.SerialHex,
	}, nil
}

func (a *PKIAdapter) GetRootCA(ctx context.Context, _ *pb.GetRootCARequest) (*pb.GetRootCAResponse, error) {
	rootCert := a.pkiSvc.RootCert()
	if rootCert == nil {
		return nil, status.Error(codes.Internal, "internal server error")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	return &pb.GetRootCAResponse{CertPem: string(certPEM)}, nil
}

func (a *PKIAdapter) RevokeCert(ctx context.Context, req *pb.RevokeCertRequest) (*pb.RevokeCertResponse, error) {
	if err := a.pkiSvc.RevokeCert(ctx, &service.RevokeCertRequest{
		SerialHex: req.SerialHex,
		OrgID:     req.OrgId,
		Reason:    int(req.Reason),
	}); err != nil {
		return nil, toStatusError(err)
	}
	return &pb.RevokeCertResponse{Success: true}, nil
}

func (a *PKIAdapter) GetCRL(ctx context.Context, req *pb.GetCRLRequest) (*pb.GetCRLResponse, error) {
	orgCACert, orgCAKey, err := a.pkiSvc.LoadOrgCA(ctx, req.OrgId)
	if err != nil {
		return nil, toStatusError(err)
	}

	resp, err := a.pkiSvc.GetCRL(ctx, &service.GetCRLRequest{
		OrgID:      req.OrgId,
		DeltaOnly:  req.DeltaOnly,
		IssuerCert: orgCACert,
		IssuerKey:  orgCAKey,
	})
	if err != nil {
		return nil, toStatusError(err)
	}

	return &pb.GetCRLResponse{
		CrlDer:    resp.CRLDER,
		CrlNumber: resp.CRLNumber,
		IsDelta:   resp.IsDelta,
	}, nil
}

func (a *PKIAdapter) CheckOCSP(ctx context.Context, req *pb.CheckOCSPRequest) (*pb.CheckOCSPResponse, error) {
	resp, err := a.pkiSvc.CheckOCSP(ctx, &service.CheckOCSPRequest{
		SerialHex: req.SerialHex,
		OrgID:     req.OrgId,
	})
	if err != nil {
		return nil, toStatusError(err)
	}

	return &pb.CheckOCSPResponse{
		Status:    int32(resp.Status),
		RevokedAt: resp.RevokedAt,
	}, nil
}

// compile-time assertion
var _ pb.PKIServiceServer = (*PKIAdapter)(nil)
