package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"sync"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type orgCAEntry struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// PKIAdapter bridges the proto PKIServiceServer interface to the internal
// PKIService. It caches org CA cert+key so that IssueMemberCert can look
// them up by org_id alone.
type PKIAdapter struct {
	pb.UnimplementedPKIServiceServer
	pkiSvc *service.PKIService

	mu     sync.RWMutex
	orgCAs map[string]*orgCAEntry
}

// NewPKIAdapter creates a new PKIAdapter.
func NewPKIAdapter(pkiSvc *service.PKIService) *PKIAdapter {
	return &PKIAdapter{
		pkiSvc: pkiSvc,
		orgCAs: make(map[string]*orgCAEntry),
	}
}

func (a *PKIAdapter) CreateOrgCA(ctx context.Context, req *pb.CreateOrgCARequest) (*pb.CreateOrgCAResponse, error) {
	resp, cert, key, err := a.pkiSvc.CreateOrgCAFull(ctx, &service.CreateOrgCARequest{
		OrgID:   req.OrgId,
		OrgName: req.OrgName,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	a.mu.Lock()
	a.orgCAs[req.OrgId] = &orgCAEntry{cert: cert, key: key}
	a.mu.Unlock()

	return &pb.CreateOrgCAResponse{
		CertPem:   resp.CertPEM,
		SerialHex: resp.SerialHex,
	}, nil
}

func (a *PKIAdapter) IssueMemberCert(ctx context.Context, req *pb.IssueMemberCertRequest) (*pb.IssueMemberCertResponse, error) {
	a.mu.RLock()
	entry, ok := a.orgCAs[req.OrgId]
	a.mu.RUnlock()
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition,
			"org CA for %q not found; call CreateOrgCA first", req.OrgId)
	}

	resp, err := a.pkiSvc.IssueMemberCert(ctx, &service.IssueMemberCertRequest{
		MemberID:    req.MemberId,
		MemberEmail: req.MemberEmail,
		OrgID:       req.OrgId,
		Role:        req.Role,
		OrgCACert:   entry.cert,
		OrgCAKey:    entry.key,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	// Create Org CA wrap for the new member so they can decrypt vault entries
	memberPub, err := keys.ParseMemberCertPublicKey(resp.CertPEM)
	if err == nil {
		_ = a.pkiSvc.WrapOrgCAForMember(ctx, req.OrgId, req.MemberId, resp.SerialHex, memberPub, entry.key)
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
		return nil, status.Error(codes.Internal, "root CA not initialized")
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
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &pb.RevokeCertResponse{Success: true}, nil
}

func (a *PKIAdapter) GetCRL(ctx context.Context, req *pb.GetCRLRequest) (*pb.GetCRLResponse, error) {
	a.mu.RLock()
	entry, ok := a.orgCAs[req.OrgId]
	a.mu.RUnlock()
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition,
			"org CA for %q not found; call CreateOrgCA first", req.OrgId)
	}

	resp, err := a.pkiSvc.GetCRL(ctx, &service.GetCRLRequest{
		OrgID:      req.OrgId,
		DeltaOnly:  req.DeltaOnly,
		IssuerCert: entry.cert,
		IssuerKey:  entry.key,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
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
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	return &pb.CheckOCSPResponse{
		Status:    int32(resp.Status),
		RevokedAt: resp.RevokedAt,
	}, nil
}

// compile-time assertion
var _ pb.PKIServiceServer = (*PKIAdapter)(nil)
