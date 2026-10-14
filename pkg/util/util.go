package util

import (
        "bufio"
        "os"
        "regexp"
        "sort"
        "strings"
)

// Deduplicate returns a sorted, unique slice of strings
func Deduplicate(in []string) []string {
        seen := make(map[string]bool, len(in))
        for _, s := range in {
                s = strings.TrimSpace(s)
                if s != "" {
                        seen[s] = true
                }
        }
        out := make([]string, 0, len(seen))
        for s := range seen {
                out = append(out, s)
        }
        sort.Strings(out)
        return out
}

// ReadLines reads a file and returns its non-empty, non-comment lines
func ReadLines(path string) ([]string, error) {
        f, err := os.Open(path)
        if err != nil {
                return nil, err
        }
        defer f.Close()

        var lines []string
        sc := bufio.NewScanner(f)
        for sc.Scan() {
                line := strings.TrimSpace(sc.Text())
                if line == "" || strings.HasPrefix(line, "#") {
                        continue
                }
                lines = append(lines, line)
        }
        return lines, sc.Err()
}

// FilterByExtension returns URLs containing any of the given extensions
func FilterByExtension(urls []string, exts ...string) []string {
        var out []string
        for _, u := range urls {
                ul := strings.ToLower(u)
                for _, ext := range exts {
                        if strings.Contains(ul, ext) {
                                out = append(out, u)
                                break
                        }
                }
        }
        return out
}

// FilterByKeyword returns lines containing any of the given keywords (case-insensitive)
func FilterByKeyword(lines []string, keywords ...string) []string {
        var out []string
        for _, line := range lines {
                ll := strings.ToLower(line)
                for _, kw := range keywords {
                        if strings.Contains(ll, strings.ToLower(kw)) {
                                out = append(out, line)
                                break
                        }
                }
        }
        return out
}

// ContainsAny returns true if s contains any of the substrings
func ContainsAny(s string, subs ...string) bool {
        sl := strings.ToLower(s)
        for _, sub := range subs {
                if strings.Contains(sl, strings.ToLower(sub)) {
                        return true
                }
        }
        return false
}

// StripProtocol removes http:// or https:// and trailing slash from a URL
func StripProtocol(u string) string {
        u = strings.TrimPrefix(u, "https://")
        u = strings.TrimPrefix(u, "http://")
        u = strings.TrimSuffix(u, "/")
        return strings.TrimSpace(u)
}

// MustMkdir creates a directory and panics on error
func MustMkdir(path string) {
        if err := os.MkdirAll(path, 0755); err != nil {
                panic("could not create directory: " + path + ": " + err.Error())
        }
}

// FileExists returns true if the path exists
func FileExists(path string) bool {
        _, err := os.Stat(path)
        return err == nil
}

// JsonStr extracts a string value from a raw JSON string by key.
// This is a lightweight JSON field extractor — NOT a full JSON parser.
// It handles both quoted strings and unquoted values (numbers, booleans).
func JsonStr(s, key string) string {
        needle := `"` + key + `":`
        idx := strings.Index(s, needle)
        if idx == -1 {
                return ""
        }
        rest := strings.TrimSpace(s[idx+len(needle):])
        if strings.HasPrefix(rest, `"`) {
                rest = rest[1:]
                if end := strings.Index(rest, `"`); end != -1 {
                        return rest[:end]
                }
                return ""
        }
        if end := strings.IndexAny(rest, ",}"); end != -1 {
                return strings.TrimSpace(rest[:end])
        }
        return strings.TrimSpace(rest)
}

// Truncate shortens a string to max characters, appending "..." if truncated
func Truncate(s string, max int) string {
        if len(s) <= max {
                return s
        }
        return s[:max] + "..."
}

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// StripANSI removes ANSI escape sequences from a string
func StripANSI(s string) string {
        if !strings.Contains(s, "\x1b") {
                return s
        }
        return ansiRegex.ReplaceAllString(s, "")
}
