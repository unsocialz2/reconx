package runner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Result holds the output of a tool run
type Result struct {
	Tool     string
	Args     []string
	Lines    []string        // stdout lines only (clean results)
	Stderr   []string        // stderr lines captured separately
	Duration time.Duration
	ExitCode int
	Err      error
}

// HasResults returns true if any stdout lines were captured
func (r *Result) HasResults() bool { return len(r.Lines) > 0 }

// IsTimeout returns true if the run exceeded its deadline
func (r *Result) IsTimeout() bool {
	return r.Err != nil && strings.Contains(r.Err.Error(), "timeout")
}

// IsNotFound returns true if the binary was not found
func (r *Result) IsNotFound() bool {
	return r.Err != nil && strings.Contains(r.Err.Error(), "executable file not found")
}

// DiagString returns a human-readable diagnosis of why a tool failed
func (r *Result) DiagString() string {
	if r.Err == nil {
		return ""
	}
	switch {
	case r.IsNotFound():
		return fmt.Sprintf("%s: binary not found in PATH — install it or check 'which %s'", r.Tool, r.Tool)
	case r.IsTimeout():
		return fmt.Sprintf("%s: timed out after %s — increase timeout or use --skip-%s", r.Tool, r.Duration.Round(time.Second), r.Tool)
	case r.ExitCode == 2:
		return fmt.Sprintf("%s: exit 2 — likely bad flags or missing config (stderr: %s)", r.Tool, strings.Join(r.Stderr, " | "))
	case r.ExitCode != 0:
		return fmt.Sprintf("%s: exit %d (stderr: %s)", r.Tool, r.ExitCode, strings.Join(r.Stderr, " | "))
	default:
		return fmt.Sprintf("%s: %v", r.Tool, r.Err)
	}
}

var (
	disableAllTimeoutsMu sync.RWMutex
	disableAllTimeouts   bool
)

// SetNoTimeout globally disables timeouts for all runner.Run calls.
func SetNoTimeout(disabled bool) {
	disableAllTimeoutsMu.Lock()
	disableAllTimeouts = disabled
	disableAllTimeoutsMu.Unlock()
}

// IsNoTimeout returns true if timeouts are globally disabled.
func IsNoTimeout() bool {
	disableAllTimeoutsMu.RLock()
	defer disableAllTimeoutsMu.RUnlock()
	return disableAllTimeouts
}

// Option configures a Run call
type Option func(*runConfig)

type runConfig struct {
	timeout       time.Duration
	hardTimeout   time.Duration // always enforced, even if IsNoTimeout() is true
	stdin         string
	stdinReader   io.Reader
	stdinCloser   io.Closer
	onLine        func(string) // called for each stdout line
	onStderrLine  func(string) // called for each stderr line
	env           []string
	captureStderr bool
	filterStderr  bool // if true, don't add stderr to Lines
}

// WithTimeout sets execution timeout
func WithTimeout(d time.Duration) Option {
	return func(c *runConfig) { c.timeout = d }
}

// WithHardTimeout sets an absolute deadline that is ALWAYS enforced, even when
// global timeouts are disabled via SetNoTimeout / --no-timeout. This prevents
// network tools from hanging indefinitely in deadlocked sockets or infinite scans.
func WithHardTimeout(d time.Duration) Option {
	return func(c *runConfig) { c.hardTimeout = d }
}

// WithStdin pipes a string to the tool's stdin
func WithStdin(s string) Option {
	return func(c *runConfig) { c.stdin = s }
}

// WithStdinReader sets an io.Reader to stream into the tool's stdin
func WithStdinReader(r io.Reader) Option {
	return func(c *runConfig) { c.stdinReader = r }
}

// WithStdinFile opens a file and streams it directly into the tool's stdin
func WithStdinFile(path string) Option {
	return func(c *runConfig) {
		f, err := os.Open(path)
		if err == nil {
			c.stdinReader = f
			c.stdinCloser = f
		}
	}
}

// WithLineCallback calls fn for each stdout line in real-time
func WithLineCallback(fn func(string)) Option {
	return func(c *runConfig) { c.onLine = fn }
}

// WithStderrCallback calls fn for each stderr line
func WithStderrCallback(fn func(string)) Option {
	return func(c *runConfig) { c.onStderrLine = fn }
}

// WithEnv sets additional environment variables
func WithEnv(env []string) Option {
	return func(c *runConfig) { c.env = env }
}

// Run executes a command and returns its output.
// Stdout and stderr are captured separately.
// onLine is called for stdout only.
// Stderr is always captured into Result.Stderr for diagnostics.
// If timeout is 0 (or SetNoTimeout is true), the command runs with no deadline
// until it completes naturally or the parent context is cancelled.
func Run(ctx context.Context, name string, args []string, opts ...Option) *Result {
	cfg := &runConfig{
		timeout:       0, // 0 = no timeout, use parent ctx only
		captureStderr: true,
		filterStderr:  true,
	}
	for _, o := range opts {
		o(cfg)
	}

	effectiveTimeout := cfg.timeout
	if IsNoTimeout() {
		effectiveTimeout = cfg.hardTimeout
	} else if cfg.hardTimeout > 0 && (effectiveTimeout == 0 || cfg.hardTimeout < effectiveTimeout) {
		effectiveTimeout = cfg.hardTimeout
	}

	var runCtx context.Context
	var cancel context.CancelFunc
	if effectiveTimeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, effectiveTimeout)
	} else {
		runCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	binPath := ResolveBinaryPath(name)
	cmd := exec.CommandContext(runCtx, binPath, args...)

	// Set process group ID so we can kill the entire process tree on timeout/cancel
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Environment
	if len(cfg.env) > 0 {
		cmd.Env = append(cmd.Environ(), cfg.env...)
	}

	// Stdin: If stdinReader is provided, use it directly.
	// Else if stdin string is provided, pipe it via strings.NewReader.
	// Otherwise explicitly provide an empty reader so child tools never block on stdin.
	if cfg.stdinCloser != nil {
		defer cfg.stdinCloser.Close()
	}
	if cfg.stdinReader != nil {
		cmd.Stdin = cfg.stdinReader
	} else if cfg.stdin != "" {
		cmd.Stdin = strings.NewReader(cfg.stdin)
	} else {
		cmd.Stdin = strings.NewReader("")
	}

        // Pipes
        stdoutPipe, err := cmd.StdoutPipe()
        if err != nil {
                return &Result{Tool: name, Args: args, Err: fmt.Errorf("stdout pipe: %w", err)}
        }
        stderrPipe, err := cmd.StderrPipe()
        if err != nil {
                return &Result{Tool: name, Args: args, Err: fmt.Errorf("stderr pipe: %w", err)}
        }

        start := time.Now()
        if err := cmd.Start(); err != nil {
                return &Result{Tool: name, Args: args, Err: fmt.Errorf("start: %w", err)}
        }

        var (
                mu          sync.Mutex
                stdoutLines []string
                stderrLines []string
                stderrBuf   bytes.Buffer
        )

        // Collect stdout
        collectStdout := func() {
                sc := bufio.NewScanner(stdoutPipe)
                sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
                for sc.Scan() {
                        line := strings.TrimSpace(sc.Text())
                        if line == "" {
                                continue
                        }
                        mu.Lock()
                        stdoutLines = append(stdoutLines, line)
                        mu.Unlock()
                        if cfg.onLine != nil {
                                cfg.onLine(line)
                        }
                }
        }

        // Collect stderr — always captured, never mixed into Lines
        collectStderr := func() {
                sc := bufio.NewScanner(stderrPipe)
                sc.Buffer(make([]byte, 1*1024*1024), 1*1024*1024)
                for sc.Scan() {
                        line := strings.TrimSpace(sc.Text())
                        if line == "" {
                                continue
                        }
                        mu.Lock()
                        stderrLines = append(stderrLines, line)
                        stderrBuf.WriteString(line + "\n")
                        mu.Unlock()
                        if cfg.onStderrLine != nil {
                                cfg.onStderrLine(line)
                        }
                }
        }

        var wg sync.WaitGroup
        wg.Add(2)
        go func() { defer wg.Done(); collectStdout() }()
        go func() { defer wg.Done(); collectStderr() }()

        // Watchdog: when runCtx is cancelled (timeout or parent cancel),
        // kill the entire process group so child processes (nuclei
        // templates, katana headless chrome, etc.) don't become zombies.
        // The previous code killed AFTER cmd.Wait() which is too late —
        // the process is already reaped and SIGKILL is a no-op.
        //
        // Two channels so we don't double-close on either path:
        //   kill       — closed by the main path once cmd.Wait() returns
        //                so the watchdog knows to exit if ctx hasn't fired.
        //   watchdogDone — closed by the watchdog once it has actually
        //                  returned (used for the deferred join below).
        kill := make(chan struct{})
        watchdogDone := make(chan struct{})
        go func() {
                defer close(watchdogDone)
                select {
                case <-runCtx.Done():
                        if cmd.Process != nil {
                                _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
                        }
                case <-kill:
                }
        }()

        wg.Wait()
        runErr := cmd.Wait()
        dur := time.Since(start)
        close(kill)             // tell watchdog to exit (process already finished)
        <-watchdogDone          // wait for the watchdog goroutine to fully return

        // Extract exit code
        exitCode := 0
        if runErr != nil {
                if exitErr, ok := runErr.(*exec.ExitError); ok {
                        exitCode = exitErr.ExitCode()
                }
        }

        // Classify timeout
        if runCtx.Err() == context.DeadlineExceeded {
                runErr = fmt.Errorf("timeout after %s", effectiveTimeout.Round(time.Second))
        }

        return &Result{
                Tool:     name,
                Args:     args,
                Lines:    stdoutLines,
                Stderr:   stderrLines,
                Duration: dur,
                ExitCode: exitCode,
                Err:      runErr,
        }
}

// ResolveBinaryPath locates the proper binary, checking ~/go/bin and system paths
// before ~/.local/bin to prevent Python packages from shadowing Go security tools.
func ResolveBinaryPath(name string) string {
	if strings.Contains(name, "/") {
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, "go", "bin", name),
		filepath.Join("/usr", "local", "bin", name),
		filepath.Join("/usr", "local", "go", "bin", name),
		filepath.Join("/usr", "bin", name),
		filepath.Join(home, ".local", "bin", name),
	}

	for _, cand := range candidates {
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			// ~/.local/bin (Python tooling) shadows Go security tools
			// (httpx, subfinder, dnsx, nuclei, naabu, etc. all have Python
			// pip packages with the same name). If a ~/go/bin version
			// exists, always prefer it.
			if strings.Contains(cand, ".local/bin") {
				goBin := filepath.Join(home, "go", "bin", name)
				if _, err := os.Stat(goBin); err == nil {
					return goBin
				}
			}
			return cand
		}
	}

	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return name
}

// IsAvailable checks whether a binary exists in PATH or Go bin dirs
func IsAvailable(name string) bool {
	p := ResolveBinaryPath(name)
	if _, err := os.Stat(p); err == nil {
		return true
	}
	_, err := exec.LookPath(name)
	return err == nil
}

// WhichPath returns the full path of a binary, or empty string
func WhichPath(name string) string {
	p := ResolveBinaryPath(name)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}

// Version runs `name --version` and returns the first line of output
func Version(name string) string {
	r := Run(context.Background(), name, []string{"--version"},
		WithTimeout(5*time.Second))
	if r.HasResults() {
		return r.Lines[0]
	}
	if len(r.Stderr) > 0 {
		return r.Stderr[0]
	}
	return "unknown"
}

// CheckTools returns a map of tool name → available
func CheckTools(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = IsAvailable(n)
	}
	return out
}
