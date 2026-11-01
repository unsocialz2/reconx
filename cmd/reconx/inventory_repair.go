package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/inventory"
	"github.com/unsocialz2/reconx/internal/modules/report"
	"github.com/unsocialz2/reconx/internal/modules/screenshot"
	"github.com/unsocialz2/reconx/internal/scope"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
)

// runInventoryRepair is an in-place recovery operation on an existing scan.
// It never re-enumerates subdomains or runs httpx, Nuclei, ports or other phases.
// Permissions and scheme restrictions come from the original scan's manifest.
func runInventoryRepair(scanDir string, screenshotWorkers int) error {
	dir, err := filepath.Abs(scanDir)
	if err != nil {
		return err
	}
	var saved struct {
		SchemaVersion int           `json:"schema_version"`
		Scope         config.Scope  `json:"scope"`
		Target        config.Target `json:"target"`
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return fmt.Errorf("inventory repair requires a saved scan manifest: %w", err)
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		return fmt.Errorf("invalid saved scan manifest: %w", err)
	}
	if saved.SchemaVersion != 1 || saved.Scope.Imported == nil {
		return fmt.Errorf("inventory repair requires a versioned inventory scan with imported scope")
	}
	wildcards := 0
	for _, a := range saved.Scope.Imported.Assets {
		if !a.Excluded && (a.Kind == "wildcard" || a.Kind == "wildcard-origin") {
			wildcards++
		}
	}
	if wildcards == 0 {
		return fmt.Errorf("saved scan has no eligible wildcard assets")
	}
	cfg := config.DefaultConfig()
	cfg.InventoryOnly = true
	cfg.ScreenshotWorkers = screenshotWorkers
	cfg.Target = saved.Target
	cfg.Scope = saved.Scope
	filter := scope.New(cfg)
	st, err := store.LoadSnapshot(filepath.Join(dir, "checkpoint.json"), filter.IsInScope)
	if err != nil {
		return fmt.Errorf("inventory repair requires a saved checkpoint: %w", err)
	}
	if len(st.GetHosts()) == 0 {
		return fmt.Errorf("no saved HTTP observations; cannot repair screenshots without HTTP observations")
	}
	log := logger.New(false, filepath.Join(dir, "inventory-repair.log"))
	defer log.Close()
	log.Info("Reusing %d saved HTTP observations; no discovery or HTTP probing", len(st.GetHosts()))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	screenErr := screenshot.New(cfg, st, log, dir).RunInventory(ctx)
	// Always rewrite the report from existing data even when a few captures
	// failed, so links and any successfully captured screenshots are visible.
	reportErr := report.Generate(st, saved.Target.Domains, dir)
	inventoryErr := inventory.Generate(st.Snapshot(), saved.Scope.Imported, dir)
	if reportErr == nil && inventoryErr == nil {
		log.Info("Inventory report regenerated: %s", filepath.Join(dir, "inventory", "index.html"))
	}
	return errors.Join(screenErr, reportErr, inventoryErr)
}
