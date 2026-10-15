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
	budget, cancel := context.WithTimeout(ctx, total)
	defer cancel()
	var failures []error
	dir, _ := ctx.Value(taskDirectoryKey{}).(string)
	for offset := 0; offset < len(items); offset += size {
		if budget.Err() != nil {
			failure := fmt.Errorf("batch budget exhausted: %w", budget.Err())
			failures = append(failures, failure)
			if observer, ok := ctx.Value(observerKey{}).(func(*Result)); ok {
				observer(&Result{Tool: name, Err: failure, Duration: time.Since(start)})
			}
			break
		}
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
		for i, a := range identityArgs {
			if a == inputFlag && inputFlag != "" && i+1 < len(identityArgs) {
				identityArgs[i+1] = "<batch-input>"
			}
		}
		identity, _ := json.Marshal([]any{"v1.2", name, identityArgs, batch, tool, workers, header})
		key := fmt.Sprintf("%x", sha256.Sum256(identity))
		file := ""
		if dir != "" {
			file = filepath.Join(dir, key+".json")
		}
		var cached Result
		if file != "" {
			if data, err := os.ReadFile(file); err == nil && json.Unmarshal(data, &cached) == nil && cached.ExitCode == 0 {
				aggregate.Lines = append(aggregate.Lines, cached.Lines...)
				if callbacks.onLine != nil {
					for _, line := range cached.Lines {
						callbacks.onLine(line)
					}
				}
				continue
			}
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
		if result.Err != nil {
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
