package runner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type taskDirectoryKey struct{}

func WithTaskDirectory(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, taskDirectoryKey{}, dir)
}

// RunInputBatches bounds each batch independently, journals completed work and
// replays it on resume. A failed batch does not prevent later batches running.
// inputFlag selects a file-input flag (-S/-i); empty means stdin.
func RunInputBatches(ctx context.Context, name string, args []string, input string, size int, total time.Duration, inputFlag string, opts ...Option) *Result {
	start := time.Now()
	aggregate := &Result{Tool: name, Args: args}
	if size < 1 {
		size = 32
	}
	var items []string
	seen := map[string]bool{}
	for _, line := range strings.Split(input, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !seen[line] {
			seen[line] = true
			items = append(items, line)
		}
	}
	// Parse callback options once; cached successes must replay the same parsers.
	callbacks := &runConfig{}
	for _, opt := range opts {
		opt(callbacks)
	}
	if callbacks.stdinCloser != nil {
		callbacks.stdinCloser.Close()
	}
	if total <= 0 {
		total = 30 * time.Minute
	}
	var budget context.Context
	budgetReported := false
	var failures []error
	dir, _ := ctx.Value(taskDirectoryKey{}).(string)
	for offset := 0; offset < len(items); offset += size {
		batch := strings.Join(items[offset:min(offset+size, len(items))], "\n")
		policy, _ := ctx.Value(policyKey{}).(*Policy)
		// The ephemeral scope proxy address is transport state, not task identity.
		var tool ToolPolicy
		workers := 0
		header := ""
		if policy != nil {
			_, tool, _ = toolPolicy(policy, name)
			workers = policy.Workers
			header = policy.Header
		}
		identityArgs := append([]string(nil), args...)
		keyName := name
		if policy != nil {
			keyName, _, _ = toolPolicy(policy, name)
		}
		pacing := map[string][]string{"httpx": {"-threads", "-rate-limit", "-timeout"}, "katana": {"-c", "-p", "-rl"}, "hakrawler": {"-t"}, "gospider": {"-t", "-c"}}
		for i, arg := range identityArgs {
			for _, flag := range pacing[keyName] {
				if arg == flag && i+1 < len(identityArgs) {
					identityArgs[i+1] = "<pacing>"
				} else if strings.HasPrefix(arg, flag+"=") {
					identityArgs[i] = flag + "=<pacing>"
				}
			}
		}
		for i, a := range identityArgs {
			if a == inputFlag && inputFlag != "" && i+1 < len(identityArgs) {
				identityArgs[i+1] = "<batch-input>"
			}
		}
		legacyArgs := append([]string(nil), args...)
		for i, a := range legacyArgs {
			if a == inputFlag && inputFlag != "" && i+1 < len(legacyArgs) {
				legacyArgs[i+1] = "<batch-input>"
			}
		}
		legacyIdentity, _ := json.Marshal([]any{"v1.2", name, legacyArgs, batch, tool, workers, header})
		semanticTool := tool
		semanticTool.Timeout = 0
		semanticTool.RateLimit = 0
		identity, _ := json.Marshal([]any{"v2", name, identityArgs, batch, semanticTool, header})
		key := fmt.Sprintf("%x", sha256.Sum256(identity))
		file := ""
		if dir != "" {
			file = filepath.Join(dir, key+".json")
		}
		if file != "" && IsRefresh(ctx) {
			invalidationErrors := len(failures)
			if err := os.MkdirAll(dir, 0700); err == nil {
				if err := os.WriteFile(file+".invalid", []byte("refresh pending"), 0600); err != nil {
					failures = append(failures, err)
				}
			} else {
				failures = append(failures, err)
			}
			for _, path := range []string{file, filepath.Join(dir, fmt.Sprintf("%x.json", sha256.Sum256(legacyIdentity)))} {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					failures = append(failures, fmt.Errorf("invalidating cached task: %w", err))
				}
			}
			if len(failures) > invalidationErrors {
				break
			}
		}
		var cached Result
		if file != "" && !IsRefresh(ctx) {
			data, readErr := os.ReadFile(file)
			if readErr != nil {
				if _, invalid := os.Stat(file + ".invalid"); os.IsNotExist(invalid) {
					data, readErr = os.ReadFile(filepath.Join(dir, fmt.Sprintf("%x.json", sha256.Sum256(legacyIdentity))))
				}
			}
			if readErr == nil && json.Unmarshal(data, &cached) == nil && cached.ExitCode == 0 && cached.Err == nil {
				aggregate.Lines = append(aggregate.Lines, cached.Lines...)
				RecordTask(ctx, name, "reused", len(strings.Split(batch, "\n")))
				if callbacks.onLine != nil {
					for _, line := range cached.Lines {
						callbacks.onLine(line)
					}
				}
				continue
			}
		}
		if budget == nil {
			var cancel context.CancelFunc
			budget, cancel = context.WithTimeoutCause(ctx, total, ErrSourceBudget)
			defer cancel()
		}
		if budget.Err() != nil {
			RecordTask(ctx, name, "pending", len(strings.Split(batch, "\n")))
			if !budgetReported {
				reason := "source budget exhausted"
				kind := "source-budget"
				if ctx.Err() != nil {
					reason = "parent scan cancelled"
					kind = ""
				}
				failure := fmt.Errorf("%s: %s; pending batches remain retryable: %w", name, reason, budget.Err())
				failures = append(failures, failure)
				budgetReported = true
				aggregate.TimeoutKind = kind
				if observer, ok := ctx.Value(observerKey{}).(func(*Result)); ok {
					observer(&Result{Tool: name, Err: failure, TimeoutKind: kind, Duration: time.Since(start)})
				}
			}
			continue
		}
		actual := append([]string(nil), args...)
		batchOpts := append([]Option(nil), opts...)
		var temp string
		if inputFlag != "" {
			f, err := os.CreateTemp("", "reconx-batch-*.txt")
			if err != nil {
				failures = append(failures, err)
				break
			}
			temp = f.Name()
			_, err = f.WriteString(batch)
			closeErr := f.Close()
			if err != nil || closeErr != nil {
				os.Remove(temp)
				failures = append(failures, errors.Join(err, closeErr))
				break
			}
			actual = MergeFlags(actual, []string{inputFlag, temp})
		} else {
			batchOpts = append(batchOpts, WithStdin(batch))
		}
		result := Run(budget, name, actual, batchOpts...)
		if temp != "" {
			os.Remove(temp)
		}
		aggregate.Lines = append(aggregate.Lines, result.Lines...)
		aggregate.Stderr = append(aggregate.Stderr, result.Stderr...)
		state := "completed"
		if result.Err != nil {
			state = "partial"
		}
		RecordTask(ctx, name, state, len(strings.Split(batch, "\n")))
		if result.Err != nil {
			if errors.Is(context.Cause(budget), ErrSourceBudget) {
				aggregate.TimeoutKind = "source-budget"
			}
			failures = append(failures, result.Err)
		} else if file != "" {
			// Only successful batches are reusable; partial batches remain retryable.
			data, err := json.Marshal(result)
			if err == nil {
				err = os.MkdirAll(dir, 0700)
			}
			if err == nil {
				err = os.WriteFile(file+".tmp", data, 0600)
			}
			if err == nil {
				err = os.Rename(file+".tmp", file)
				if err == nil {
					_ = os.Remove(file + ".invalid")
				}
			}
			if err != nil {
				failures = append(failures, fmt.Errorf("saving batch: %w", err))
			}
		}
	}
	aggregate.Err = errors.Join(failures...)
	aggregate.Duration = time.Since(start)
	return aggregate
}
