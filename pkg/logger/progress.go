package logger

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ToolStatus represents the current state of a running tool.
//
// Throughput tracking:
//   - countHistory keeps (timestamp, count) samples for the last 10 seconds
//   - throughput() computes results/sec from those samples
//   - lastActivity is updated whenever count increases OR Heartbeat() is called
//     by the tool (e.g. on every stdout line, even if dedup hasn't bumped count)
//
// Stuck detection:
//   - If now-lastActivity > 30s, the tool is "idle" (shown in yellow)
//   - If now-lastActivity > 60s, the tool is "stuck" (shown in red, pulsing)
type ToolStatus struct {
	Name         string
	Target       string
	State        string // "running", "done", "error", "timeout", "skipped"
	Count        int
	Start        time.Time
	Message      string // final message for done/error
	lastActivity time.Time
	countHistory []sample // for throughput calc (last 10s)
}

type sample struct {
	at    time.Time
	count int
}

// stuckIdleAfter is how long without activity before a tool turns yellow.
const stuckIdleAfter = 30 * time.Second

// stuckAlertAfter is how long without activity before a tool turns red.
const stuckAlertAfter = 60 * time.Second

// ProgressBoard shows all running tools in a live-updating table with
// throughput, stuck detection, and an aggregate summary header.
type ProgressBoard struct {
	mu       sync.Mutex
	tools    map[string]*ToolStatus
	order    []string // insertion order for stable display
	logger   *Logger
	done     chan struct{}
	stopped  bool
	lines    int  // how many lines we drew last frame (for cursor-up)
	paused   bool // paused while printing a permanent log line

	// liveStats is an optional callback that returns live counts for the
	// summary header (subdomains, hosts, urls, findings, secrets, ports).
	// Set by the pipeline so the board can show real-time totals.
	liveStats func() map[string]int
}

// NewProgressBoard creates and starts a progress board
func (l *Logger) NewProgressBoard() *ProgressBoard {
	b := &ProgressBoard{
		tools:  make(map[string]*ToolStatus),
		logger: l,
		done:   make(chan struct{}),
	}
	go b.run()
	return b
}

// SetLiveStats registers a callback that returns live counts for the
// summary header line. The pipeline sets this so the board can show
// "TOTAL: 1247 subs | 89 live | 5421 urls" updating in real time.
func (b *ProgressBoard) SetLiveStats(fn func() map[string]int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.liveStats = fn
}

// Register adds a tool to the board as "running"
func (b *ProgressBoard) Register(name, target string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if _, exists := b.tools[name]; !exists {
		b.order = append(b.order, name)
	}
	b.tools[name] = &ToolStatus{
		Name:         name,
		Target:       target,
		State:        "running",
		Start:        now,
		lastActivity: now,
		countHistory: []sample{{at: now, count: 0}},
	}
}

// Update sets live count for a running tool and records a throughput sample.
func (b *ProgressBoard) Update(name string, count int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ok := b.tools[name]
	if !ok {
		return
	}
	now := time.Now()
	if count > t.Count {
		t.lastActivity = now
	}
	t.Count = count
	t.countHistory = append(t.countHistory, sample{at: now, count: count})
	// Trim history to last 10 seconds
	cutoff := now.Add(-10 * time.Second)
	for len(t.countHistory) > 2 && t.countHistory[0].at.Before(cutoff) {
		t.countHistory = t.countHistory[1:]
	}
}

// Heartbeat records activity for a tool without changing its count.
// Use this when a tool emits output lines that don't bump the count
// (e.g., httpx probing a host that turns out to be dead). This keeps
// the tool from looking "stuck" while it's actively working.
func (b *ProgressBoard) Heartbeat(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if t, ok := b.tools[name]; ok {
		t.lastActivity = time.Now()
	}
}

// Done marks a tool as finished
func (b *ProgressBoard) Done(name string, count int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if t, ok := b.tools[name]; ok {
		t.State = "done"
		t.Count = count
		t.Message = fmt.Sprintf("%d results", count)
		t.lastActivity = time.Now()
	}
}

// SourceStats returns a snapshot of per-tool results and states, sorted by
// result count descending. Used to print the per-source yield summary after
// a phase completes so low-yield or skipped sources are immediately visible
// without digging through the debug log.
func (b *ProgressBoard) SourceStats() []ToolStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]ToolStatus, 0, len(b.tools))
	for _, t := range b.tools {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].State == out[j].State {
			return out[i].Count > out[j].Count
		}
		// done/timeout first, then error, then skipped
		rank := map[string]int{"done": 0, "timeout": 1, "running": 2, "error": 3, "skipped": 4}
		return rank[out[i].State] < rank[out[j].State]
	})
	return out
}

// Fail marks a tool as failed
func (b *ProgressBoard) Fail(name, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if t, ok := b.tools[name]; ok {
		t.State = "error"
		t.Message = reason
		t.lastActivity = time.Now()
	}
}

// Timeout marks a tool as timed-out with partial results
func (b *ProgressBoard) Timeout(name string, partial int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if t, ok := b.tools[name]; ok {
		t.State = "timeout"
		t.Count = partial
		t.Message = fmt.Sprintf("kept %d partial results", partial)
		t.lastActivity = time.Now()
	}
}

// Skip marks a tool as skipped
func (b *ProgressBoard) Skip(name, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.tools[name]; !exists {
		b.order = append(b.order, name)
	}
	now := time.Now()
	b.tools[name] = &ToolStatus{
		Name:         name,
		State:        "skipped",
		Message:      reason,
		Start:        now,
		lastActivity: now,
	}
}

// Stop ends the progress board and clears it
func (b *ProgressBoard) Stop() {
	b.mu.Lock()
	if b.stopped {
		b.mu.Unlock()
		return
	}
	b.stopped = true
	b.mu.Unlock()
	close(b.done)
	time.Sleep(100 * time.Millisecond)
	b.clear()
}

// PauseForLog clears the board temporarily so a permanent log line can print cleanly
func (b *ProgressBoard) PauseForLog() {
	b.mu.Lock()
	b.paused = true
	b.mu.Unlock()
	b.clear()
}

// ResumeAfterLog re-enables the board after a permanent log line was printed
func (b *ProgressBoard) ResumeAfterLog() {
	b.mu.Lock()
	b.paused = false
	b.mu.Unlock()
}

func (b *ProgressBoard) run() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	frame := 0
	for {
		select {
		case <-b.done:
			return
		case <-ticker.C:
			b.redraw(frame)
			frame++
		}
	}
}

var boardFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// throughput returns results per second over the last 10 seconds.
// Returns 0 if the tool just started or hasn't received results recently.
func (t *ToolStatus) throughput() float64 {
	if len(t.countHistory) < 2 {
		return 0
	}
	first := t.countHistory[0]
	last := t.countHistory[len(t.countHistory)-1]
	dt := last.at.Sub(first.at)
	if dt < time.Second {
		return 0
	}
	return float64(last.count-first.count) / dt.Seconds()
}

// idleFor returns how long since the tool last had activity.
func (t *ToolStatus) idleFor() time.Duration {
	if t.State != "running" {
		return 0
	}
	return time.Since(t.lastActivity)
}

func (b *ProgressBoard) redraw(frame int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.paused || len(b.order) == 0 {
		return
	}

	// Move cursor up to overwrite previous board
	if b.lines > 0 {
		fmt.Printf("\033[%dA", b.lines)
	}

	spin := boardFrames[frame%len(boardFrames)]
	drawn := 0

	// ── Summary header (line 1) ────────────────────────────────────────────
	// Shows live totals + tools running/done/failed — gives the user an
	// instant "is anything happening?" answer at a glance.
	running, done, failed, skipped := 0, 0, 0, 0
	for _, name := range b.order {
		switch b.tools[name].State {
		case "running":
			running++
		case "done", "timeout":
			done++
		case "error":
			failed++
		case "skipped":
			skipped++
		}
	}

	headerParts := []string{
		c(hBlack, "▶"),
		cb(hWhite, fmt.Sprintf("%d running", running)),
	}
	if done > 0 {
		headerParts = append(headerParts, c(hGreen, fmt.Sprintf("%d ✓", done)))
	}
	if failed > 0 {
		headerParts = append(headerParts, c(hRed, fmt.Sprintf("%d ✗", failed)))
	}
	if skipped > 0 {
		headerParts = append(headerParts, c(hBlack, fmt.Sprintf("%d ○", skipped)))
	}

	// Live totals from the pipeline store
	if b.liveStats != nil {
		stats := b.liveStats()
		if s := stats["subdomains"]; s > 0 {
			headerParts = append(headerParts, c(hCyan, "│"), cb(hCyan, fmt.Sprintf("%d subs", s)))
		}
		if h := stats["live_hosts"]; h > 0 {
			headerParts = append(headerParts, c(hGreen, fmt.Sprintf("%d live", h)))
		}
		if u := stats["urls"]; u > 0 {
			headerParts = append(headerParts, c(hYellow, fmt.Sprintf("%d urls", u)))
		}
		if f := stats["findings"]; f > 0 {
			headerParts = append(headerParts, c(hRed, fmt.Sprintf("%d findings", f)))
		}
		if sec := stats["secrets"]; sec > 0 {
			headerParts = append(headerParts, c(hRed, fmt.Sprintf("%d secrets", sec)))
		}
	}

	fmt.Printf("\r\033[2K  %s\n", strings.Join(headerParts, " "))
	drawn++

	// ── Per-tool lines ────────────────────────────────────────────────────
	for _, name := range b.order {
		t := b.tools[name]
		elapsed := time.Since(t.Start).Round(time.Second)

		var icon, nameStr, detail, elapsedStr, throughputStr string

		switch t.State {
		case "running":
			// Stuck detection — change color based on idle time
			idle := t.idleFor()
			switch {
			case idle > stuckAlertAfter:
				// Stuck: red, pulsing icon
				if frame%2 == 0 {
					icon = cb(hRed, "!")
				} else {
					icon = cb(red, "!")
				}
				nameStr = c(hRed, fmt.Sprintf("%-22s", name))
			case idle > stuckIdleAfter:
				// Idle: yellow, slow spin
				icon = c(yellow, spin)
				nameStr = c(yellow, fmt.Sprintf("%-22s", name))
			default:
				// Active: cyan, fast spin
				icon = c(cyan, spin)
				nameStr = c(cyan, fmt.Sprintf("%-22s", name))
			}

			// Count or target
			if t.Count > 0 {
				detail = c(hGreen, fmt.Sprintf("%-22s", fmt.Sprintf("%d found", t.Count)))
			} else {
				detail = c(hBlack, fmt.Sprintf("%-22s", truncate(t.Target, 22)))
			}

			// Throughput (results per second, last 10s)
			tp := t.throughput()
			if tp > 0.1 {
				throughputStr = c(hGreen, fmt.Sprintf("%6.1f/s", tp))
			} else if t.Count > 0 {
				throughputStr = c(hBlack, "      –")
			} else {
				throughputStr = c(hBlack, "      –")
			}

			// Idle indicator (only show if idle > 5s)
			if idle > 5*time.Second {
				throughputStr += " " + c(hBlack, fmt.Sprintf("(idle %ds)", int(idle.Seconds())))
			}

			elapsedStr = c(yellow, fmt.Sprintf("  %s", elapsed))

		case "done":
			icon = cb(green, "✓")
			nameStr = c(hBlack, fmt.Sprintf("%-22s", name))
			detail = c(hGreen, fmt.Sprintf("%-22s", t.Message))
			throughputStr = c(hBlack, "      –")
			elapsedStr = c(hBlack, fmt.Sprintf("  %s", elapsed))

		case "timeout":
			icon = c(yellow, "⏱")
			nameStr = c(hBlack, fmt.Sprintf("%-22s", name))
			detail = c(yellow, fmt.Sprintf("%-22s", t.Message))
			throughputStr = c(hBlack, "      –")
			elapsedStr = c(hBlack, fmt.Sprintf("  %s", elapsed))

		case "error":
			icon = cb(red, "✗")
			nameStr = c(hBlack, fmt.Sprintf("%-22s", name))
			detail = c(hRed, fmt.Sprintf("%-22s", truncate(t.Message, 22)))
			throughputStr = c(hBlack, "      –")
			elapsedStr = c(hBlack, fmt.Sprintf("  %s", elapsed))

		case "skipped":
			icon = c(hBlack, "○")
			nameStr = c(hBlack, fmt.Sprintf("%-22s", name))
			detail = c(hBlack, fmt.Sprintf("%-22s", truncate(t.Message, 22)))
			throughputStr = c(hBlack, "      –")
			elapsedStr = ""
		}

		fmt.Printf("\r\033[2K    %s %s %s %s%s\n",
			icon, nameStr, detail, throughputStr, elapsedStr)
		drawn++
	}

	// ── Footer hint (only when at least one tool is running) ──────────────
	if running > 0 {
		fmt.Printf("\r\033[2K  %s\n",
			c(hBlack, "  press Ctrl+C to stop · tools run in parallel · yellow=idle 30s · red=stuck 60s"))
		drawn++
	}

	b.lines = drawn
}

func (b *ProgressBoard) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lines > 0 {
		fmt.Printf("\033[%dA", b.lines)
		for i := 0; i < b.lines; i++ {
			fmt.Printf("\r\033[2K\n")
		}
		fmt.Printf("\033[%dA", b.lines)
		b.lines = 0
	}
}

// ── Logger integration: permanent log lines pause/resume the board ────────────

// InfoBoard prints a permanent info line, pausing the board
func (l *Logger) InfoBoard(board *ProgressBoard, format string, args ...interface{}) {
	if board != nil {
		board.PauseForLog()
		defer board.ResumeAfterLog()
	}
	l.Info(format, args...)
}

// WarnBoard prints a permanent warning line
func (l *Logger) WarnBoard(board *ProgressBoard, format string, args ...interface{}) {
	if board != nil {
		board.PauseForLog()
		defer board.ResumeAfterLog()
	}
	l.Warn(format, args...)
}

// DebugBoard prints a debug line (only if verbose)
func (l *Logger) DebugBoard(board *ProgressBoard, format string, args ...interface{}) {
	if board != nil && l.verbose {
		board.PauseForLog()
		defer board.ResumeAfterLog()
	}
	l.Debug(format, args...)
}

// FindingBoard prints a permanent finding line
func (l *Logger) FindingBoard(board *ProgressBoard, severity, name, target string) {
	if board != nil {
		board.PauseForLog()
		defer board.ResumeAfterLog()
	}
	l.Finding(severity, name, target)
}
