package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

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

func randomHex(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf)
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
