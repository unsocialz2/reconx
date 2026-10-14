package runner

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRun_BasicCommand(t *testing.T) {
	r := Run(context.Background(), "echo", []string{"hello reconx"})
	if r.Err != nil {
		t.Fatalf("unexpected error: %v", r.Err)
	}
	if !r.HasResults() || !strings.Contains(r.Lines[0], "hello reconx") {
		t.Errorf("unexpected output: %v", r.Lines)
	}
}

func TestRun_Stdin(t *testing.T) {
	r := Run(context.Background(), "cat", nil,
		WithStdin("line1\nline2\nline3"))
	if r.Err != nil {
		t.Fatalf("unexpected error: %v", r.Err)
	}
	if len(r.Lines) != 3 {
		t.Errorf("expected 3 lines, got %d: %v", len(r.Lines), r.Lines)
	}
}

func TestRun_Timeout(t *testing.T) {
	start := time.Now()
	r := Run(context.Background(), "sleep", []string{"30"},
		WithTimeout(150*time.Millisecond))
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Errorf("timeout didn't fire fast enough: took %s", elapsed)
	}
	if r.Err == nil {
		t.Error("expected error for timed-out process")
	}
	if !r.IsTimeout() {
		t.Errorf("expected IsTimeout()=true, err=%v", r.Err)
	}
}

func TestRun_LineCallback(t *testing.T) {
	var got []string
	Run(context.Background(), "echo", []string{"callback test"},
		WithLineCallback(func(line string) {
			got = append(got, line)
		}))
	if len(got) == 0 || !strings.Contains(got[0], "callback test") {
		t.Errorf("callback not called or wrong value: %v", got)
	}
}

func TestRun_StderrCallback(t *testing.T) {
	var stderrLines []string
	// write to stderr via sh
	r := Run(context.Background(), "sh", []string{"-c", "echo errline >&2; echo outline"},
		WithStderrCallback(func(line string) {
			stderrLines = append(stderrLines, line)
		}))

	if len(r.Lines) == 0 || r.Lines[0] != "outline" {
		t.Errorf("expected stdout 'outline', got: %v", r.Lines)
	}
	if len(stderrLines) == 0 || stderrLines[0] != "errline" {
		t.Errorf("expected stderr 'errline', got: %v", stderrLines)
	}
	// Stderr must NOT appear in Lines
	for _, l := range r.Lines {
		if strings.Contains(l, "errline") {
			t.Error("stderr line leaked into stdout Lines")
		}
	}
}

func TestRun_StderrCaptured(t *testing.T) {
	r := Run(context.Background(), "sh", []string{"-c", "echo err >&2"})
	if len(r.Stderr) == 0 {
		t.Error("expected stderr to be captured")
	}
	if r.Stderr[0] != "err" {
		t.Errorf("unexpected stderr: %v", r.Stderr)
	}
	// Must not appear in Lines
	if len(r.Lines) != 0 {
		t.Errorf("stderr leaked into Lines: %v", r.Lines)
	}
}

func TestRun_ExitCode(t *testing.T) {
	r := Run(context.Background(), "sh", []string{"-c", "exit 42"})
	if r.ExitCode != 42 {
		t.Errorf("expected exit code 42, got %d", r.ExitCode)
	}
}

func TestRun_ExitCodeZeroOnSuccess(t *testing.T) {
	r := Run(context.Background(), "true", nil)
	if r.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", r.ExitCode)
	}
	if r.Err != nil {
		t.Errorf("expected no error, got: %v", r.Err)
	}
}

func TestRun_InvalidCommand(t *testing.T) {
	r := Run(context.Background(), "this_binary_does_not_exist_xyz_reconx", nil)
	if r.Err == nil {
		t.Error("expected error for non-existent binary")
	}
	if !r.IsNotFound() {
		t.Errorf("expected IsNotFound()=true, err=%v", r.Err)
	}
	diag := r.DiagString()
	if !strings.Contains(diag, "not found") {
		t.Errorf("DiagString should mention 'not found', got: %s", diag)
	}
}

func TestRun_DiagString_Timeout(t *testing.T) {
	r := Run(context.Background(), "sleep", []string{"30"},
		WithTimeout(100*time.Millisecond))
	diag := r.DiagString()
	if !strings.Contains(diag, "timeout") {
		t.Errorf("DiagString should mention timeout, got: %s", diag)
	}
}

func TestRun_DiagString_ExitCode(t *testing.T) {
	r := Run(context.Background(), "sh", []string{"-c", "exit 2"})
	diag := r.DiagString()
	if diag == "" {
		t.Error("DiagString should not be empty for exit 2")
	}
}

func TestRun_HasResults(t *testing.T) {
	r1 := Run(context.Background(), "echo", []string{"hi"})
	if !r1.HasResults() {
		t.Error("expected HasResults=true")
	}

	r2 := Run(context.Background(), "true", nil)
	if r2.HasResults() {
		t.Error("expected HasResults=false for no output")
	}
}

func TestRun_LargeOutput(t *testing.T) {
	// Generate 10000 lines via seq
	r := Run(context.Background(), "seq", []string{"1", "10000"},
		WithTimeout(10*time.Second))
	if r.Err != nil {
		t.Fatalf("unexpected error: %v", r.Err)
	}
	if len(r.Lines) != 10000 {
		t.Errorf("expected 10000 lines, got %d", len(r.Lines))
	}
}

func TestRun_EnvVar(t *testing.T) {
	r := Run(context.Background(), "sh", []string{"-c", "echo $MY_TEST_VAR"},
		WithEnv([]string{"MY_TEST_VAR=hello_reconx"}))
	if r.Err != nil {
		t.Fatalf("unexpected error: %v", r.Err)
	}
	if len(r.Lines) == 0 || r.Lines[0] != "hello_reconx" {
		t.Errorf("env var not passed through, got: %v", r.Lines)
	}
}

func TestIsAvailable(t *testing.T) {
	if !IsAvailable("echo") {
		t.Error("echo should be available on all systems")
	}
	if IsAvailable("this_tool_does_not_exist_xyz_reconx_777") {
		t.Error("fake tool should not be available")
	}
}

func TestWhichPath(t *testing.T) {
	p := WhichPath("echo")
	if p == "" {
		t.Error("WhichPath('echo') should return a path")
	}
	if !strings.HasPrefix(p, "/") {
		t.Errorf("WhichPath should return absolute path, got: %s", p)
	}
}

func TestVersion(t *testing.T) {
	v := Version("sh")
	// sh --version may fail on some systems but should not panic
	_ = v
}

func TestCheckTools(t *testing.T) {
	avail := CheckTools([]string{"echo", "cat", "sh", "fake_tool_xyz_reconx"})
	if !avail["echo"]  { t.Error("echo should be available") }
	if !avail["cat"]   { t.Error("cat should be available") }
	if !avail["sh"]    { t.Error("sh should be available") }
	if avail["fake_tool_xyz_reconx"] { t.Error("fake tool should not be available") }
}

func TestRun_HardTimeoutEnforcedEvenWithNoTimeout(t *testing.T) {
	SetNoTimeout(true)
	defer SetNoTimeout(false)

	start := time.Now()
	// sleep for 30s, but hardTimeout is 150ms. Must be killed in ~150ms!
	r := Run(context.Background(), "sleep", []string{"30"},
		WithTimeout(10*time.Second),
		WithHardTimeout(150*time.Millisecond))
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Errorf("hard timeout didn't enforce deadline when NoTimeout=true: took %s", elapsed)
	}
	if r.Err == nil || !r.IsTimeout() {
		t.Errorf("expected IsTimeout()=true, err=%v", r.Err)
	}
}

func TestRun_DefaultEmptyStdinDoesNotBlock(t *testing.T) {
	// 'cat' without stdin would block forever on terminal stdin if not piped.
	// With empty reader default, cat exits immediately with 0 lines and exit code 0.
	start := time.Now()
	r := Run(context.Background(), "cat", nil, WithTimeout(2*time.Second))
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Errorf("cat took too long, likely blocked on stdin: took %s", elapsed)
	}
	if r.Err != nil {
		t.Errorf("unexpected error: %v", r.Err)
	}
	if len(r.Lines) != 0 {
		t.Errorf("expected 0 lines from empty stdin, got %v", r.Lines)
	}
}
