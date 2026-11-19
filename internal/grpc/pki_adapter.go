package grpc

import (
	"context"
	"encoding/pem"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/authn"
	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// BootstrapSessionHeader is the admin session minted by CreateOrgCA.
	// organization. Managed member keys are not returned to the client.
	BootstrapSessionHeader = "x-minikms-bootstrap-session"
	// BootstrapMemberSerialHeader is that admin certificate's serial.
	BootstrapMemberSerialHeader = "x-minikms-member-serial"
)

// BootstrapSessionIssuer mints a session for a managed member key that stays
// on the server. *service.SessionService implements it.
type BootstrapSessionIssuer interface {
	IssueBootstrapSession(ctx context.Context, memberID, orgID, role, certSerial string) (string, error)
}

// PKIAdapter bridges the proto PKIServiceServer interface to the internal
// PKIService. Durable CA material is loaded by the service for every request,
// allowing calls to move freely between replicas.
type PKIAdapter struct {
	pb.UnimplementedPKIServiceServer
	pkiSvc    *service.PKIService
	bootstrap BootstrapSessionIssuer
}

// NewPKIAdapter creates a new PKIAdapter.
func NewPKIAdapter(pkiSvc *service.PKIService) *PKIAdapter {
	return &PKIAdapter{pkiSvc: pkiSvc}
}

// SetBootstrapSessionIssuer enables a one-time admin session when an
// organization CA is created. The member private key is stored and not returned.
func (a *PKIAdapter) SetBootstrapSessionIssuer(issuer BootstrapSessionIssuer) {
	a.bootstrap = issuer
}

func (a *PKIAdapter) CreateOrgCA(ctx context.Context, req *pb.CreateOrgCARequest) (*pb.CreateOrgCAResponse, error) {
	resp, token, serial, err := a.bootstrapNewOrg(ctx, req)
	if err != nil {
		return nil, err
	}
	if token != "" {
		if err := grpc.SetHeader(ctx, metadata.Pairs(
			BootstrapSessionHeader, token,
			BootstrapMemberSerialHeader, serial,
		)); err != nil {
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}
	return resp, nil
}

func (a *PKIAdapter) bootstrapNewOrg(ctx context.Context, req *pb.CreateOrgCARequest) (*pb.CreateOrgCAResponse, string, string, error) {
	if req == nil {
		req = &pb.CreateOrgCARequest{}
	}
	resp, cert, key, _, err := a.pkiSvc.CreateOrgCAFull(ctx, &service.CreateOrgCARequest{
		OrgID:   req.OrgId,
		OrgName: req.OrgName,
	})
	if err != nil {
		return nil, "", "", toStatusError(err)
	}
	out := &pb.CreateOrgCAResponse{CertPem: resp.CertPEM, SerialHex: resp.SerialHex}
	// Existing organizations still need an admin session. The first CreateOrgCA
	// is the only time one was minted, and the API cannot decrypt the stored
	// member key until it has that session.
	if a.bootstrap == nil || cert == nil || key == nil {
		return out, "", "", nil
	}

	memberID := "bootstrap-admin-" + req.OrgId
	issued, err := a.pkiSvc.IssueMemberCert(ctx, &service.IssueMemberCertRequest{
		MemberID:    memberID,
		MemberEmail: memberID + "@local",
		OrgID:       req.OrgId,
		Role:        "admin",
		OrgCACert:   cert,
		OrgCAKey:    key,
	})
	if err != nil {
		return nil, "", "", toStatusError(err)
	}
	// The managed private key stays in certificate storage.
	issued.KeyPEM = ""
	if pub, pubErr := keys.ParseMemberCertPublicKey(issued.CertPEM); pubErr == nil {
		_ = a.pkiSvc.WrapOrgCAForMember(ctx, req.OrgId, memberID, issued.SerialHex, pub, key)
	}
	token, err := a.bootstrap.IssueBootstrapSession(ctx, memberID, req.OrgId, "admin", issued.SerialHex)
	if err != nil {
		return nil, "", "", toStatusError(err)
	}
	if token == "" || issued.SerialHex == "" {
		return nil, "", "", status.Error(codes.Internal, "internal server error")
	}
	return out, token, issued.SerialHex, nil
}

func (a *PKIAdapter) CreateOrgCACSR(ctx context.Context, req *pb.CreateOrgCACSRRequest) (*pb.CreateOrgCACSRResponse, error) {
	csr, err := a.pkiSvc.CreateOrgCACSR(ctx, req.OrgId, req.OrgName)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &pb.CreateOrgCACSRResponse{CsrPem: csr}, nil
}

func (a *PKIAdapter) InstallOrgCA(ctx context.Context, req *pb.InstallOrgCARequest) (*pb.CreateOrgCAResponse, error) {
	if req == nil {
		req = &pb.InstallOrgCARequest{}
	}
	if _, err := authorizePKI(ctx, req.OrgId, true); err != nil {
		return nil, toStatusError(err)
	}
	resp, err := a.pkiSvc.InstallOrgCA(ctx, req.OrgId, req.CertPem, req.ChainPem)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &pb.CreateOrgCAResponse{CertPem: resp.CertPEM, SerialHex: resp.SerialHex}, nil
}

func (a *PKIAdapter) IssueMemberCert(ctx context.Context, req *pb.IssueMemberCertRequest) (*pb.IssueMemberCertResponse, error) {
	if req == nil {
		req = &pb.IssueMemberCertRequest{}
	}
	if _, err := authorizePKI(ctx, req.OrgId, false); err != nil {
		return nil, toStatusError(err)
	}
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
		KeyPem:    "",
		SerialHex: resp.SerialHex,
	}, nil
}

func (a *PKIAdapter) CreateEnvCA(ctx context.Context, req *pb.CreateEnvCARequest) (*pb.CreateEnvCAResponse, error) {
	resp, err := a.pkiSvc.CreateEnvCA(ctx, req.OrgId, req.EnvId, req.Name)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &pb.CreateEnvCAResponse{CertPem: resp.CertPEM, SerialHex: resp.SerialHex}, nil
}

func (a *PKIAdapter) IssueLeafCert(ctx context.Context, req *pb.IssueLeafCertRequest) (*pb.IssueLeafCertResponse, error) {
	orgCACert, orgCAKey, err := a.pkiSvc.LoadIssuingCA(ctx, req.OrgId, req.EnvId)
	if err != nil {
		return nil, toStatusError(err)
	}

	resp, err := a.pkiSvc.IssueLeafCert(ctx, &service.IssueLeafCertRequest{
		OrgID:        req.OrgId,
		CommonName:   req.CommonName,
		DNSSans:      req.DnsSans,
		TTLDays:      int(req.TtlDays),
		KeyAlgorithm: req.KeyAlgorithm,
		OrgCACert:    orgCACert,
		OrgCAKey:     orgCAKey,
	})
	if err != nil {
		return nil, toStatusError(err)
	}
	return &pb.IssueLeafCertResponse{
		CertPem:   resp.CertPEM,
		KeyPem:    resp.KeyPEM,
		SerialHex: resp.SerialHex,
	}, nil
}

func (a *PKIAdapter) SignCSR(ctx context.Context, req *pb.SignCSRRequest) (*pb.SignCSRResponse, error) {
	orgCACert, orgCAKey, err := a.pkiSvc.LoadIssuingCA(ctx, req.OrgId, req.EnvId)
	if err != nil {
		return nil, toStatusError(err)
	}

	resp, err := a.pkiSvc.SignCSR(ctx, &service.SignCSRServiceRequest{
		OrgID:     req.OrgId,
		CSRPEM:    req.CsrPem,
		TTLDays:   int(req.TtlDays),
		OrgCACert: orgCACert,
		OrgCAKey:  orgCAKey,
	})
	if err != nil {
		return nil, toStatusError(err)
	}
	return &pb.SignCSRResponse{
		CertPem:   resp.CertPEM,
		SerialHex: resp.SerialHex,
	}, nil
}

func (a *PKIAdapter) GetRootCA(ctx context.Context, _ *pb.GetRootCARequest) (*pb.GetRootCAResponse, error) {
	rootCert := a.pkiSvc.RootCert()
	if rootCert == nil {
		return nil, status.Error(codes.FailedPrecondition, "root CA is not configured")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	return &pb.GetRootCAResponse{CertPem: string(certPEM)}, nil
}

func (a *PKIAdapter) RevokeCert(ctx context.Context, req *pb.RevokeCertRequest) (*pb.RevokeCertResponse, error) {
	if req == nil {
		req = &pb.RevokeCertRequest{}
	}
	if _, err := authorizePKI(ctx, req.OrgId, true); err != nil {
		return nil, toStatusError(err)
	}
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

func authorizePKI(ctx context.Context, orgID string, admin bool) (authn.Principal, error) {
	principal, ok := authn.FromContext(ctx)
	if !ok {
		return authn.Principal{}, service.NewDomainError(service.ErrorUnauthenticated, "authentication required", nil)
	}
	if admin && principal.Role != "admin" && principal.Role != "master" {
		return authn.Principal{}, service.NewDomainError(service.ErrorPermissionDenied, "admin role required", nil)
	}
	if principal.TenantID == "" || principal.TenantID != orgID {
		return authn.Principal{}, service.NewDomainError(service.ErrorPermissionDenied, "tenant access denied", nil)
	}
	return principal, nil
}

// compile-time assertion
var _ pb.PKIServiceServer = (*PKIAdapter)(nil)
