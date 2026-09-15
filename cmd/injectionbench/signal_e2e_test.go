//go:build unix

package main_test

import (
	"bufio"
	"errors"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestBinaryServeExitsCleanlyOnSIGTERM(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.CommandContext(t.Context(), bin, "serve", "--mode", "vulnerable", "--addr", "127.0.0.1:0") //nolint:gosec // G204: bin is the binary this test just built
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	listening := make(chan struct{})
	go func() {
		var once sync.Once
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "listening on ") {
				once.Do(func() { close(listening) })
			}
		}
	}()
	select {
	case <-listening:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("serve never reported its listening address")
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("serve exited with code %d after SIGTERM, want 0", exitErr.ExitCode())
		} else if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("serve did not exit within 10s of SIGTERM")
	}
}
