package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ansiRe matches ANSI escape sequences for stripping from log file output
var ansiRe = regexp.MustCompile(`\[[0-9;]*m`)

// stripANSI removes all ANSI color codes from a string
func stripANSI(s string) string {
	return ansiRe.ReplaceAllString(s, "")
}

// Level represents log severity
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// ANSI color codes
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	hBlack  = "\033[90m"
	hRed    = "\033[91m"
	hGreen  = "\033[92m"
	hYellow = "\033[93m"
	hCyan   = "\033[96m"
	hWhite  = "\033[97m"
)

func c(color, s string) string  { return color + s + reset }
func cb(color, s string) string { return color + bold + s + reset }

// Logger is the central structured logging component.
// It writes colored output to stderr and optionally a plain log file.
type Logger struct {
	mu       sync.Mutex
	verbose  bool
	start    time.Time
	logFile  *os.File   // plain text log file (no ANSI)
	counters map[string]int
}

// New creates a new Logger. If logPath != "", also writes to that file.
func New(verbose bool, logPath string) *Logger {
	l := &Logger{
		verbose:  verbose,
		start:    time.Now(),
		counters: make(map[string]int),
	}
	if logPath != "" {
		// Ensure parent directory exists
		if dir := filepath.Dir(logPath); dir != "." && dir != "" {
			_ = os.MkdirAll(dir, 0755)
		}
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			l.logFile = f
			l.filePrintf("[START] ReconX scan started at %s\n", time.Now().Format(time.RFC3339))
		} else {
			fmt.Fprintf(os.Stderr, "[reconx] warning: could not create log file %s: %v\n", logPath, err)
		}
	}
	return l
}

// Close flushes and closes the log file
func (l *Logger) Close() {
	if l.logFile != nil {
		l.filePrintf("[END] ReconX scan finished at %s — elapsed %s\n",
			time.Now().Format(time.RFC3339),
			time.Since(l.start).Round(time.Second))
		l.logFile.Close()
	}
}

// IncrCounter increments a named counter and returns the new value
func (l *Logger) IncrCounter(name string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counters[name]++
	return l.counters[name]
}

// GetCounter returns the current value of a named counter
func (l *Logger) GetCounter(name string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counters[name]
}

func (l *Logger) ts() string {
	e := time.Since(l.start)
	return c(hBlack, fmt.Sprintf("[%02d:%02d]", int(e.Minutes()), int(e.Seconds())%60))
}

func (l *Logger) tsPlain() string {
	e := time.Since(l.start)
	return fmt.Sprintf("[%02d:%02d]", int(e.Minutes()), int(e.Seconds())%60)
}

func (l *Logger) filePrintf(format string, args ...interface{}) {
	if l.logFile != nil {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprint(l.logFile, stripANSI(msg))
	}
}

// Banner prints the ASCII startup banner
func (l *Logger) Banner(version string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Print(cb(hGreen, `
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║ ╚███╔╝ 
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║ ██╔██╗ 
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║██╔╝╚██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝╚═╝  ╚═╝
`))
	fmt.Printf("  %s  Bug Bounty Automation Framework %s\n\n",
		c(hBlack, "//"), c(hGreen, version))
}

// Phase prints a phase header block
func (l *Logger) Phase(phase, desc string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Println()
	fmt.Printf("  %s %s\n", cb(magenta, "╔══ PHASE:"), cb(hWhite, strings.ToUpper(phase)))
	fmt.Printf("  %s  %s\n", c(magenta, "║"), c(hBlack, desc))
	fmt.Printf("  %s\n", c(magenta, "╚══════════════════════════════════════════════"))
	fmt.Println()
	l.filePrintf("\n[PHASE] %s — %s\n", strings.ToUpper(phase), desc)
}

// PhaseComplete prints phase completion summary
func (l *Logger) PhaseComplete(phase string, count int, dur time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf("✓ %s — %d results in %s", phase, count, dur.Round(time.Second))
	fmt.Printf("  %s %s — %s results in %s\n",
		cb(green, "✓"), c(hWhite, phase),
		cb(hCyan, fmt.Sprintf("%d", count)),
		c(hBlack, dur.Round(time.Second).String()))
	l.filePrintf("[PHASE-DONE] %s\n", msg)
}

// Tool logs a tool execution start with its full command
func (l *Logger) Tool(name, target string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("  %s %s %-20s %s\n",
		l.ts(), c(hBlack, "▶"), c(cyan, name), c(hBlack, "→ "+target))
	l.filePrintf("%s [RUN] %s → %s\n", l.tsPlain(), name, target)
}

// ToolCmd logs a tool execution with the exact command being run
func (l *Logger) ToolCmd(name string, args []string, stdin string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cmdStr := name + " " + strings.Join(args, " ")
	if stdin != "" && len(stdin) < 100 {
		cmdStr += " <<< '" + stdin + "'"
	} else if stdin != "" {
		cmdStr += fmt.Sprintf(" <<< [%d bytes stdin]", len(stdin))
	}
	// Always show in verbose mode
	if l.verbose {
		fmt.Printf("  %s %s %s\n", l.ts(), c(hBlack, "  CMD:"), c(hBlack, cmdStr))
	}
	l.filePrintf("%s [CMD] %s\n", l.tsPlain(), cmdStr)
}

// ToolDone logs tool completion with result count and timing
func (l *Logger) ToolDone(name string, count int, dur time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("  %s %s %-20s %s %s\n",
		l.ts(), cb(green, "✓"), c(cyan, name),
		cb(hGreen, fmt.Sprintf("%d results", count)),
		c(hBlack, "("+dur.Round(time.Millisecond*100).String()+")"))
	l.filePrintf("%s [DONE] %s — %d results (%s)\n",
		l.tsPlain(), name, count, dur.Round(time.Millisecond*100))
}

// ToolSkipped logs that a tool was skipped and why
func (l *Logger) ToolSkipped(name, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("  %s %s %-20s %s\n",
		l.ts(), c(hBlack, "○"), c(hBlack, name), c(hBlack, "skipped — "+reason))
	l.filePrintf("%s [SKIP] %s — %s\n", l.tsPlain(), name, reason)
}

// ToolError logs a tool failure with full diagnostic info
func (l *Logger) ToolError(name string, err error, stderr []string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	fmt.Printf("  %s %s %-20s %s\n",
		l.ts(), cb(red, "✗"), c(cyan, name), c(hRed, err.Error()))

	// Always show stderr lines when tool fails — this is the key diagnostic info
	if len(stderr) > 0 {
		fmt.Printf("  %s %s stderr output:\n", l.ts(), c(hRed, "  ↳"))
		shown := stderr
		if len(shown) > 8 {
			shown = shown[:8]
		}
		for _, line := range shown {
			fmt.Printf("  %s      %s\n", l.ts(), c(hRed, "  "+line))
		}
		if len(stderr) > 8 {
			fmt.Printf("  %s      %s\n", l.ts(),
				c(hBlack, fmt.Sprintf("  ... and %d more stderr lines (check reconx.log)", len(stderr)-8)))
		}
	}

	l.filePrintf("%s [ERROR] %s: %v\n", l.tsPlain(), name, err)
	for _, line := range stderr {
		l.filePrintf("%s [STDERR:%s] %s\n", l.tsPlain(), name, line)
	}
}

// ToolTimeout logs a timeout with partial results info
func (l *Logger) ToolTimeout(name string, partialCount int, timeout time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("  %s %s %-20s %s %s\n",
		l.ts(), c(yellow, "⏱"), c(cyan, name),
		c(yellow, fmt.Sprintf("timed out after %s", timeout.Round(time.Second))),
		c(hBlack, fmt.Sprintf("(kept %d partial results)", partialCount)))
	l.filePrintf("%s [TIMEOUT] %s after %s — %d partial results\n",
		l.tsPlain(), name, timeout.Round(time.Second), partialCount)
}

// Finding logs a vulnerability or secret finding
func (l *Logger) Finding(severity, name, target string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("  %s %s [%s] %s  %s\n",
		l.ts(), cb(hRed, "⚑ FINDING"),
		colorSeverity(severity),
		cb(hWhite, name),
		c(hBlack, target))
	l.filePrintf("%s [FINDING] [%s] %s — %s\n", l.tsPlain(), strings.ToUpper(severity), name, target)
}

// Secret logs a discovered secret/credential
func (l *Logger) Secret(secretType, source, hint string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("  %s %s [%s] from %s — %s\n",
		l.ts(), cb(hRed, "🔑 SECRET"),
		cb(hRed, secretType),
		c(cyan, source),
		c(hBlack, hint))
	l.filePrintf("%s [SECRET] [%s] source=%s hint=%s\n", l.tsPlain(), secretType, source, hint)
}

// NewSubdomain logs a newly discovered subdomain (only in verbose)
func (l *Logger) NewSubdomain(sub, source string) {
	if !l.verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("  %s %s %s %s\n",
		l.ts(), c(hGreen, "+"), cb(hWhite, sub), c(hBlack, "["+source+"]"))
	l.filePrintf("%s [SUB] %s via %s\n", l.tsPlain(), sub, source)
}

// LiveHost logs a newly discovered live host (only in verbose)
func (l *Logger) LiveHost(domain string, code int, title, server string) {
	if !l.verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	statusColor := hGreen
	if code >= 400 {
		statusColor = yellow
	}
	if code >= 500 {
		statusColor = hRed
	}
	fmt.Printf("  %s %s %s %s %s %s\n",
		l.ts(),
		c(hBlack, "↳"),
		cb(hWhite, domain),
		cb(statusColor, fmt.Sprintf("[%d]", code)),
		c(hBlack, server),
		c(hBlack, truncate(title, 50)))
	l.filePrintf("%s [HOST] %s status=%d server=%s title=%s\n",
		l.tsPlain(), domain, code, server, title)
}

// ScopeFiltered logs a scope-filtered item
func (l *Logger) ScopeFiltered(value, reason string) {
	if !l.verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("  %s %s %s\n", l.ts(), c(hBlack, "⊘"), c(hBlack, "out-of-scope: "+value+" ("+reason+")"))
	l.filePrintf("%s [SCOPE-OUT] %s reason=%s\n", l.tsPlain(), value, reason)
}

// Info logs an informational message
func (l *Logger) Info(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s %s %s\n", l.ts(), c(cyan, "ℹ"), msg)
	l.filePrintf("%s [INFO] %s\n", l.tsPlain(), msg)
}

// Success logs a success
func (l *Logger) Success(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s %s %s\n", l.ts(), cb(green, "✓"), msg)
	l.filePrintf("%s [SUCCESS] %s\n", l.tsPlain(), msg)
}

// Warn logs a warning
func (l *Logger) Warn(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s %s %s\n", l.ts(), c(yellow, "⚠"), c(yellow, msg))
	l.filePrintf("%s [WARN] %s\n", l.tsPlain(), msg)
}

// Error logs an error
func (l *Logger) Error(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s %s %s\n", l.ts(), cb(red, "✗"), cb(hRed, msg))
	l.filePrintf("%s [ERROR] %s\n", l.tsPlain(), msg)
}

// Debug logs only when verbose is on — always written to log file
func (l *Logger) Debug(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.verbose {
		fmt.Printf("  %s %s %s\n", l.ts(), c(hBlack, "·"), c(hBlack, msg))
	}
	l.filePrintf("%s [DEBUG] %s\n", l.tsPlain(), msg)
}

// Stat prints a key=value summary line
func (l *Logger) Stat(key string, value interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("    %s %s\n",
		c(hBlack, fmt.Sprintf("%-32s", key+":")),
		cb(hCyan, fmt.Sprintf("%v", value)))
	l.filePrintf("    %-32s %v\n", key+":", value)
}

// Separator prints a visual separator line
func (l *Logger) Separator() {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("  %s\n", c(hBlack, "─────────────────────────────────────────────"))
}

// Raw writes a message with no formatting — for tool output passthrough
func (l *Logger) Raw(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("    %s\n", c(hBlack, msg))
	l.filePrintf("    %s\n", msg)
}

func colorSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return cb(hRed, "CRITICAL")
	case "high":
		return c(red, "HIGH    ")
	case "medium":
		return c(yellow, "MEDIUM  ")
	case "low":
		return c(green, "LOW     ")
	default:
		return c(hBlack, "INFO    ")
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// ── Progress Spinner ──────────────────────────────────────────────────────────

// Spinner shows a live spinning indicator while a tool is running.
// Call Start() to begin, Stop() when done.
type Spinner struct {
	mu      sync.Mutex
	name    string
	target  string
	start   time.Time
	done    chan struct{}
	stopped bool
	log     *Logger
	counter *int64 // optional live counter — use sync/atomic to update
}

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// StartSpinner creates and starts a spinner for a running tool.
// Returns a Spinner — call .Stop() when the tool finishes.
func (l *Logger) StartSpinner(name, target string) *Spinner {
	s := &Spinner{
		name:   name,
		target: target,
		start:  time.Now(),
		done:   make(chan struct{}),
		log:    l,
	}
	go s.run()
	return s
}

// StartSpinnerWithCounter creates a spinner that shows a live result count.
// Pass a pointer to an int64 that gets incremented as results arrive.
func (l *Logger) StartSpinnerWithCounter(name, target string, counter *int64) *Spinner {
	s := &Spinner{
		name:    name,
		target:  target,
		start:   time.Now(),
		done:    make(chan struct{}),
		log:     l,
		counter: counter,
	}
	go s.run()
	return s
}

func (s *Spinner) run() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	frame := 0
	for {
		select {
		case <-s.done:
			// Clear the spinner line
			fmt.Printf("\r\033[2K")
			return
		case <-ticker.C:
			elapsed := time.Since(s.start).Round(time.Second)
			spin  := c(cyan, spinFrames[frame%len(spinFrames)])
			name  := c(cyan, fmt.Sprintf("%-20s", s.name))
			tgt   := c(hBlack, s.target)
			elaps := c(hBlack, fmt.Sprintf("(%s)", elapsed))

			if s.counter != nil {
				cnt := fmt.Sprintf("%d found", *s.counter)
				fmt.Printf("\r  %s %s %s %s %s    ",
					spin, name, tgt,
					c(hGreen, cnt), elaps)
			} else {
				fmt.Printf("\r  %s %s %s %s    ",
					spin, name, tgt, elaps)
			}
			frame++
		}
	}
}

// Stop ends the spinner. Call this when the tool finishes.
// It clears the spinner line — the caller should then call ToolDone/ToolError.
func (s *Spinner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.stopped {
		s.stopped = true
		close(s.done)
		time.Sleep(50 * time.Millisecond) // let goroutine clear the line
	}
}
