package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/config"
	grpcadapter "github.com/envsync-cloud/minikms/internal/grpc"
	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/pki"
	"github.com/envsync-cloud/minikms/internal/ratelimit"
	"github.com/envsync-cloud/minikms/internal/service"
	"github.com/envsync-cloud/minikms/internal/store"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Load root key — this is the ONLY place the root key is loaded (Issue #1)
	rootKeyHolder := keys.GetRootKeyHolder()
	if err := rootKeyHolder.Load(cfg.RootKey); err != nil {
		log.Fatalf("Failed to load root key: %v", err)
	}
	log.Println("Root key loaded successfully")

	// Initialize stores
	pgStore, err := store.NewPostgresStore(ctx, cfg.DBUrl)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	defer pgStore.Close()
	log.Println("PostgreSQL connected")

	redisStore, err := store.NewRedisStore(ctx, cfg.RedisURL)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer redisStore.Close()
	log.Println("Redis connected")

	// Initialize key management
	orgKeyMgr := keys.NewOrgKeyManager(rootKeyHolder)
	dekManager := keys.NewAppDEKManager(orgKeyMgr, pgStore, cfg.MaxEncryptionsPerKey)
	versionManager := keys.NewKeyVersionManager(pgStore, cfg.MaxEncryptionsPerKey)

	// Initialize audit logger
	auditLogger := audit.NewAuditLogger(pgStore)

	// Initialize rate limiter
	_ = ratelimit.NewRateLimiter(redisStore.Client(), cfg.RateLimitPerSecond, cfg.RateLimitBurst)

	// Generate PKI root CA
	rootCert, rootKey, _, err := pki.CreateRootCA("miniKMS Root CA", 10*365*24*time.Hour)
	if err != nil {
		log.Fatalf("Failed to create PKI root CA: %v", err)
	}
	log.Println("PKI root CA generated")

	// Initialize Org CA wrap manager
	orgCAWrapMgr := keys.NewOrgCAWrapManager(pgStore)

	// Generate session signing key (P-256 for JWT ES256)
	sessionSigningKey, err := service.GenerateSessionSigningKey()
	if err != nil {
		log.Fatalf("Failed to generate session signing key: %v", err)
	}
	log.Println("Session signing key generated")

	// Initialize services
	kmsSvc := service.NewKMSService(dekManager, auditLogger)
	keySvc := service.NewKeyService(dekManager, versionManager, auditLogger)
	auditSvc := service.NewAuditService(auditLogger, pgStore)
	pkiSvc := service.NewPKIService(rootCert, rootKey, auditLogger, pgStore)
	pkiSvc.SetOrgCAWrapManager(orgCAWrapMgr)
	pkiSvc.SetShamirConfig(cfg.ShamirTotalShares, cfg.ShamirThreshold)

	sessionSvc := service.NewSessionService(
		sessionSigningKey,
		"minikms",
		8*time.Hour, // default session TTL
		pgStore,     // token registry
		pgStore,     // cert store
		pgStore,     // policy store
		auditLogger,
	)

	vaultSvc := service.NewVaultService(
		dekManager,
		orgCAWrapMgr,
		pgStore,
		auditLogger,
		sessionSvc,
	)

	// Create gRPC adapters
	kmsAdapter := grpcadapter.NewKMSAdapter(kmsSvc, keySvc)
	pkiAdapter := grpcadapter.NewPKIAdapter(pkiSvc)
	auditAdapter := grpcadapter.NewAuditAdapter(auditSvc)
	vaultAdapter := grpcadapter.NewVaultAdapter(vaultSvc)
	sessionAdapter := grpcadapter.NewSessionAdapter(sessionSvc)

	// Create gRPC server
	var opts []grpc.ServerOption
	if cfg.TLSEnabled {
		creds, err := credentials.NewServerTLSFromFile(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			log.Fatalf("Failed to load TLS credentials: %v", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	grpcServer := grpc.NewServer(opts...)

	// Register gRPC services
	pb.RegisterKMSServiceServer(grpcServer, kmsAdapter)
	pb.RegisterPKIServiceServer(grpcServer, pkiAdapter)
	pb.RegisterAuditServiceServer(grpcServer, auditAdapter)
	pb.RegisterVaultServiceServer(grpcServer, vaultAdapter)
	pb.RegisterSessionServiceServer(grpcServer, sessionAdapter)

	// Register health check
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("minikms", healthpb.HealthCheckResponse_SERVING)

	// Enable server reflection for debugging
	reflection.Register(grpcServer)

	// Start listening
	listener, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.GRPCAddr, err)
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		fmt.Printf("\nReceived signal %v, shutting down...\n", sig)
		healthServer.SetServingStatus("minikms", healthpb.HealthCheckResponse_NOT_SERVING)
		grpcServer.GracefulStop()
		cancel()
	}()

	log.Printf("miniKMS gRPC server starting on %s (TLS: %v)", cfg.GRPCAddr, cfg.TLSEnabled)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("gRPC server failed: %v", err)
	}
}
