package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/envsync-cloud/minikms/internal/pki"
)

// TestMiniKMSReadyAfterDelayedPostgresAndRedis is the AC-3 readiness fixture.
// One miniKMS process is started while Postgres and Redis refuse connections.
// The same process becomes gRPC-healthy after both dependencies start. Nothing
// restarts it.
func TestMiniKMSReadyAfterDelayedPostgresAndRedis(t *testing.T) {
	bin := minikmsBinary(t)
	requireDocker(t)
	t.Parallel()

	dockerPull(t, "postgres:15-alpine")
	dockerPull(t, "redis:7-alpine")

	pgPort := refusedPort(t)
	redisPort := refusedPort(t)
	grpcPort := refusedPort(t)
	pgName := dockerName("minikms-boot-pg")
	redisName := dockerName("minikms-boot-redis")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "docker", "rm", "-f", pgName, redisName).Run()
	})

	material := newBootMaterial(t)
	dbURL := fmt.Sprintf("postgres://minikms_test@127.0.0.1:%d/minikms_test?sslmode=disable", pgPort)
	redisURL := fmt.Sprintf("redis://127.0.0.1:%d/0", redisPort)
	grpcAddr := fmt.Sprintf("127.0.0.1:%d", grpcPort)
	secrets := []string{material.rootKeyHex, material.certPEM, material.caKeyPEM, material.sessionPEM, dbURL, redisURL}

	proc := startMiniKMS(t, bin, []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"TMPDIR=" + os.TempDir(),
		"MINIKMS_ALLOW_INSECURE=true",
		"MINIKMS_GRPC_ADDR=" + grpcAddr,
		"MINIKMS_DB_URL=" + dbURL,
		"MINIKMS_REDIS_URL=" + redisURL,
		"MINIKMS_ROOT_KEY=" + material.rootKeyHex,
		"MINIKMS_ROOT_CA_CERT=" + material.certPEM,
		"MINIKMS_ROOT_CA_KEY=" + material.caKeyPEM,
		"MINIKMS_SESSION_SIGNING_KEY=" + material.sessionPEM,
	})
	pid := proc.cmd.Process.Pid

	waitForLog(t, proc, "PostgreSQL ping failed (attempt 2)", 15*time.Second, secrets)
	if !processAlive(proc.cmd.Process) || proc.cmd.Process.Pid != pid {
		t.Fatalf("miniKMS did not stay up through the first Postgres failures\n%s", redactLog(proc.logs.String(), secrets))
	}

	dockerRun(t, "run", "-d", "--rm", "--pull", "never",
		"--name", pgName,
		"--tmpfs", "/var/lib/postgresql/data",
		"-e", "POSTGRES_USER=minikms_test",
		"-e", "POSTGRES_DB=minikms_test",
		"-e", "POSTGRES_HOST_AUTH_METHOD=trust",
		"-p", fmt.Sprintf("127.0.0.1:%d:5432", pgPort),
		"postgres:15-alpine",
	)
	waitForLog(t, proc, "PostgreSQL connected", 60*time.Second, secrets)
	waitForLog(t, proc, "Redis ping failed (attempt 2)", 15*time.Second, secrets)

	dockerRun(t, "run", "-d", "--rm", "--pull", "never",
		"--name", redisName,
		"-p", fmt.Sprintf("127.0.0.1:%d:6379", redisPort),
		"redis:7-alpine",
	)
	waitForServing(t, proc, grpcAddr, 45*time.Second, secrets)

	if proc.cmd.Process.Pid != pid || !processAlive(proc.cmd.Process) {
		t.Fatalf("ready process pid=%d alive=%v, started pid=%d", proc.cmd.Process.Pid, processAlive(proc.cmd.Process), pid)
	}
	logs := proc.logs.String()
	if strings.Count(logs, "Root key loaded successfully") != 1 {
		t.Fatalf("root key load count = %d, want 1 (process restarted)\n%s", strings.Count(logs, "Root key loaded successfully"), redactLog(logs, secrets))
	}
	if countLine(logs, "PostgreSQL connected") != 1 || countLine(logs, "Redis connected") != 1 {
		t.Fatalf("dependency ready lines missing\n%s", redactLog(logs, secrets))
	}
	if !strings.Contains(logs, "PostgreSQL connected after") || !strings.Contains(logs, "Redis connected after") {
		t.Fatalf("expected both dependencies to connect only after a retry\n%s", redactLog(logs, secrets))
	}
	assertPostgresQueryable(t, dbURL)
	assertRedisPing(t, redisURL)
	logBootLines(t, logs, secrets)
}

// TestMiniKMSExitsWhenPostgresStaysDown is the AC-3 permanent-failure fixture.
// With the production retry budget, a Postgres that never accepts connections
// still makes the process exit, and not on the first ping.
func TestMiniKMSExitsWhenPostgresStaysDown(t *testing.T) {
	bin := minikmsBinary(t)
	t.Parallel()

	pgPort := refusedPort(t)
	redisPort := refusedPort(t)
	grpcPort := refusedPort(t)
	rootKey := randomHex(t, 32)
	dbURL := fmt.Sprintf("postgres://minikms_test@127.0.0.1:%d/minikms_test?sslmode=disable", pgPort)
	redisURL := fmt.Sprintf("redis://127.0.0.1:%d/0", redisPort)
	secrets := []string{rootKey, dbURL, redisURL}

	started := time.Now()
	proc := startMiniKMS(t, bin, []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"TMPDIR=" + os.TempDir(),
		"MINIKMS_ALLOW_INSECURE=true",
		"MINIKMS_GRPC_ADDR=" + fmt.Sprintf("127.0.0.1:%d", grpcPort),
		"MINIKMS_DB_URL=" + dbURL,
		"MINIKMS_REDIS_URL=" + redisURL,
		"MINIKMS_ROOT_KEY=" + rootKey,
	})

	deadline := BootRetryTimeout + 90*time.Second
	var exitErr error
	exited := false
	for time.Since(started) < deadline {
		if err, done := proc.exited(); done {
			exitErr = err
			exited = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	elapsed := time.Since(started)
	logs := redactLog(proc.logs.String(), secrets)
	if !exited {
		t.Fatalf("process still running after %s\n%s", elapsed, logs)
	}
	if elapsed < BootRetryTimeout {
		t.Fatalf("exited after %s, want at least %s\n%s", elapsed, BootRetryTimeout, logs)
	}
	var exitErrTyped *exec.ExitError
	if !errors.As(exitErr, &exitErrTyped) || exitErrTyped.ExitCode() == 0 {
		t.Fatalf("exit err = %v, want non-zero\n%s", exitErr, logs)
	}
	if !strings.Contains(logs, "PostgreSQL ping failed (attempt 2)") {
		t.Fatalf("process did not retry Postgres\n%s", logs)
	}
	if !strings.Contains(logs, "PostgreSQL unavailable after "+BootRetryTimeout.String()) {
		t.Fatalf("final error did not report the boot budget\n%s", logs)
	}
	if strings.Contains(logs, "PostgreSQL connected") || strings.Contains(logs, "miniKMS gRPC server starting") {
		t.Fatalf("process became ready despite a down database\n%s", logs)
	}
	if minikmsServing(fmt.Sprintf("127.0.0.1:%d", grpcPort)) {
		t.Fatal("health reported SERVING after a permanent Postgres failure")
	}
	t.Logf("exited after %s (budget %s)", elapsed.Round(time.Millisecond), BootRetryTimeout)
	logBootLines(t, proc.logs.String(), secrets)
}

type bootMaterial struct {
	rootKeyHex string
	certPEM    string
	caKeyPEM   string
	sessionPEM string
}

func newBootMaterial(t *testing.T) bootMaterial {
	t.Helper()
	cert, key, _, err := pki.CreateRootCA("miniKMS Boot Retry Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sessionDER, err := x509.MarshalPKCS8PrivateKey(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	return bootMaterial{
		rootKeyHex: randomHex(t, 32),
		certPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		caKeyPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		sessionPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: sessionDER})),
	}
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf)
}

func dockerName(prefix string) string {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return prefix + "-" + hex.EncodeToString(buf[:])
}

type miniProc struct {
	cmd  *exec.Cmd
	logs *lockedBuffer
	mu   sync.Mutex
	done bool
	err  error
}

func startMiniKMS(t *testing.T, bin string, env []string) *miniProc {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Env = env
	cmd.Dir = t.TempDir()
	logs := &lockedBuffer{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start minikms: %v", err)
	}
	proc := &miniProc{cmd: cmd, logs: logs}
	go func() {
		err := cmd.Wait()
		proc.mu.Lock()
		proc.done = true
		proc.err = err
		proc.mu.Unlock()
	}()
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	return proc
}

func (p *miniProc) exited() (error, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err, p.done
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func waitForLog(t *testing.T, proc *miniProc, needle string, timeout time.Duration, secrets []string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err, done := proc.exited(); done {
			t.Fatalf("minikms exited before %q: %v\n%s", needle, err, redactLog(proc.logs.String(), secrets))
		}
		if strings.Contains(proc.logs.String(), needle) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %q\n%s", timeout, needle, redactLog(proc.logs.String(), secrets))
}

func waitForServing(t *testing.T, proc *miniProc, addr string, timeout time.Duration, secrets []string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err, done := proc.exited(); done {
			t.Fatalf("minikms exited before SERVING: %v\n%s", err, redactLog(proc.logs.String(), secrets))
		}
		if minikmsServing(addr) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for health SERVING\n%s", timeout, redactLog(proc.logs.String(), secrets))
}

func minikmsServing(addr string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{Service: "minikms"})
	return err == nil && resp.GetStatus() == healthpb.HealthCheckResponse_SERVING
}

func processAlive(p *os.Process) bool {
	if p == nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

func logBootLines(t *testing.T, logs string, secrets []string) {
	t.Helper()
	for _, line := range strings.Split(redactLog(logs, secrets), "\n") {
		switch {
		case strings.Contains(line, "ping failed"),
			strings.Contains(line, "connected"),
			strings.Contains(line, "unavailable after"),
			strings.Contains(line, "Failed to connect"),
			strings.Contains(line, "gRPC server starting"),
			strings.Contains(line, "Root key loaded"):
			t.Log(line)
		}
	}
}

func countLine(logs, message string) int {
	n := 0
	for _, line := range strings.Split(logs, "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), message) {
			n++
		}
	}
	return n
}

func assertPostgresQueryable(t *testing.T, dbURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	opened, err := NewPostgresStore(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres accepted by boot but NewPostgresStore failed: %v", err)
	}
	t.Cleanup(opened.Close)
	_, err = opened.GetOrgSecurityPolicy(ctx, "boot-retry-probe")
	if err != nil && !strings.Contains(err.Error(), "SQLSTATE") {
		t.Fatalf("postgres pool could not query: %v", err)
	}
}

func assertRedisPing(t *testing.T, redisURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	opened, err := NewRedisStore(ctx, redisURL)
	if err != nil {
		t.Fatalf("redis accepted by boot but NewRedisStore failed: %v", err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	if err := opened.Client().Ping(ctx).Err(); err != nil {
		t.Fatalf("redis ping after boot: %v", err)
	}
}

var pemPattern = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----`)
var urlPattern = regexp.MustCompile(`(?i)\b(?:postgres|postgresql|redis)://\S+`)

func redactLog(s string, secrets []string) string {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		s = strings.ReplaceAll(s, secret, "[redacted]")
	}
	s = pemPattern.ReplaceAllString(s, "[redacted-pem]")
	s = urlPattern.ReplaceAllString(s, "[redacted-url]")
	return s
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required for the boot-retry fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Fatalf("docker daemon is not available: %v", err)
	}
}

func dockerPull(t *testing.T, image string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "pull", image)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker pull %s: %v\n%s", image, err, out)
	}
}

func dockerRun(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", args[0], err, out)
	}
}

var (
	minikmsBinOnce sync.Once
	minikmsBin     string
	minikmsBinErr  error
)

func minikmsBinary(t *testing.T) string {
	t.Helper()
	root := moduleRoot()
	minikmsBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "minikms-boot-bin-")
		if err != nil {
			minikmsBinErr = err
			return
		}
		minikmsBin = filepath.Join(dir, "minikms")
		cmd := exec.Command("go", "build", "-o", minikmsBin, "./cmd/minikms")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			minikmsBinErr = fmt.Errorf("go build ./cmd/minikms: %w\n%s", err, out)
		}
	})
	if minikmsBinErr != nil {
		t.Fatal(minikmsBinErr)
	}
	return minikmsBin
}

func moduleRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
