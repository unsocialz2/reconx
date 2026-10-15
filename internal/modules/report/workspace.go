package report

import (
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
)

type workspace struct {
	Comparison  any                    `json:"comparison,omitempty"`
	Version     string                 `json:"version"`
	Targets     []string               `json:"targets"`
	GeneratedAt string                 `json:"generated_at"`
	Data        store.Snapshot         `json:"data"`
	Phases      map[string]phaseReport `json:"phases"`
	Scope       any                    `json:"scope"`
	Sources     []logger.ToolStatus    `json:"sources"`
	Tasks       []taskReport           `json:"tasks"`
	Parameters  []parameterReport      `json:"parameters"`
	Screenshots map[string]string      `json:"screenshots"`
	Artifacts   []artifactReport       `json:"artifacts"`
}
type phaseReport struct {
	Status     string    `json:"status"`
	Reason     string    `json:"reason"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}
type parameterReport struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Method string `json:"method"`
	Source string `json:"source"`
}
type artifactReport struct {
	Name    string `json:"name"`
	Private bool   `json:"private"`
}
type taskReport struct {
	Tool     string `json:"tool"`
	Results  int    `json:"results"`
	Duration string `json:"duration"`
}

func generateWorkspace(st *store.Store, targets []string, outDir string) error {
	snap := st.Snapshot()
	// Every data collection is complete. Pagination happens in the browser, not Go.
	secrets := snap.Secrets
	snap.Secrets = redactSecrets(snap.Secrets)
	w := workspace{Version: "1.2.0", Targets: targets, GeneratedAt: time.Now().UTC().Format(time.RFC3339), Data: snap, Phases: map[string]phaseReport{}, Screenshots: map[string]string{}}
	var manifest struct {
		Phases map[string]phaseReport `json:"phases"`
		Scope  any                    `json:"scope"`
	}
	if raw, err := os.ReadFile(filepath.Join(outDir, "manifest.json")); err == nil && json.Unmarshal(raw, &manifest) == nil {
		w.Phases = manifest.Phases
		w.Scope = manifest.Scope
	}
	if raw, err := os.ReadFile(filepath.Join(store.DataDir(outDir), "url_discovery_summary.json")); err == nil {
		_ = json.Unmarshal(raw, &w.Sources)
	}
	var subSources []logger.ToolStatus
	if raw, err := os.ReadFile(filepath.Join(store.DataDir(outDir), "subdomain_source_summary.json")); err == nil && json.Unmarshal(raw, &subSources) == nil {
		w.Sources = append(w.Sources, subSources...)
	}
	if raw, err := os.ReadFile(filepath.Join(outDir, "comparison.json")); err == nil {
		_ = json.Unmarshal(raw, &w.Comparison)
	}
	latest := time.Time{}
	for _, phase := range w.Phases {
		if phase.FinishedAt.After(latest) {
			latest = phase.FinishedAt
		}
	}
	if !latest.IsZero() && latest.After(snap.StartTime) {
		w.Data.Duration = latest.Sub(snap.StartTime).Round(time.Second).String()
	}
	seen := map[string]bool{}
	add := func(name, raw, method, source string) {
		key := name + "\x00" + raw + "\x00" + method + "\x00" + source
		if name != "" && !seen[key] {
			seen[key] = true
			w.Parameters = append(w.Parameters, parameterReport{name, raw, method, source})
		}
	}
	for _, p := range snap.ParamResults {
		for _, name := range p.Params {
			add(name, p.URL, p.Method, p.Tool)
		}
	}

	sort.Slice(w.Parameters, func(i, j int) bool {
		a, b := w.Parameters[i], w.Parameters[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.URL < b.URL
	})
	_ = filepath.WalkDir(outDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(outDir, path)
		if err == nil && rel != "report.html" {
			w.Artifacts = append(w.Artifacts, artifactReport{filepath.ToSlash(rel), true})
		}
		return nil
	})
	entries, _ := os.ReadDir(filepath.Join(outDir, "screenshots"))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		rel := "screenshots/" + entry.Name() + "/screenshot.png"
		if _, err := os.Stat(filepath.Join(outDir, rel)); err == nil {
			w.Screenshots[entry.Name()] = rel
		}
	}
	entries, _ = os.ReadDir(filepath.Join(outDir, "tasks"))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var task struct {
			Tool     string
			Lines    []string
			Duration time.Duration
		}
		if raw, err := os.ReadFile(filepath.Join(outDir, "tasks", entry.Name())); err == nil && json.Unmarshal(raw, &task) == nil {
			w.Tasks = append(w.Tasks, taskReport{filepath.Base(task.Tool), len(task.Lines), task.Duration.Round(time.Millisecond).String()})
		}
	}
	// Scrub the cloned data in place, avoiding a second JSON object graph for
	// large scans. Query mappings are derived in the browser from complete URLs.
	var scrub func(reflect.Value)
	scrub = func(v reflect.Value) {
		if !v.IsValid() {
			return
		}
		switch v.Kind() {
		case reflect.Pointer:
			if !v.IsNil() {
				scrub(v.Elem())
			}
		case reflect.Interface:
			if !v.IsNil() && v.CanSet() {
				copy := reflect.New(v.Elem().Type()).Elem()
				copy.Set(v.Elem())
				scrub(copy)
				v.Set(copy)
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Field(i).CanSet() {
					scrub(v.Field(i))
				}
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				scrub(v.Index(i))
			}
		case reflect.Map:
			iter := v.MapRange()
			for iter.Next() {
				copy := reflect.New(v.Type().Elem()).Elem()
				copy.Set(iter.Value())
				scrub(copy)
				v.SetMapIndex(iter.Key(), copy)
			}
		case reflect.String:
			if v.CanSet() {
				text := v.String()
				for _, secret := range secrets {
					if secret.Value != "" {
						text = strings.ReplaceAll(text, secret.Value, redactSecretValue(secret.Value))
					}
				}
				v.SetString(text)
			}
		}
	}
	scrub(reflect.ValueOf(&w).Elem())
	raw, err := json.Marshal(w)
	if err != nil {
		return err
	}
	// json.Marshal escapes HTML delimiters before entering the JSON script block.
	t, err := template.New("workspace").Parse(htmlTemplate)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(outDir, "report-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = t.Execute(f, struct{ JSON template.JS }{template.JS(raw)}); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(outDir, "report.html"))
}
