package urls

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
)

// A targeted retry must not replace untouched source failures with "skipped".
func mergeSourceSummary(dir, file string, current []logger.ToolStatus, selected []string) []logger.ToolStatus {
	if len(selected) == 0 {
		return current
	}
	var previous []logger.ToolStatus
	raw, err := os.ReadFile(filepath.Join(store.DataDir(dir), file))
	if err != nil || json.Unmarshal(raw, &previous) != nil {
		return current
	}
	return logger.MergeSourceStats(previous, current, selected)
}
