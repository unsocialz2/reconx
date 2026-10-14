package params

import (
"net/url"
"sort"
"strings"
)

// ExtractParamsFromURL parses a URL and returns all query parameter keys found.
// e.g. "https://example.com/search?q=test&page=1" → ["page", "q"]
func ExtractParamsFromURL(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery == "" {
		return nil
	}
	vals, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// ExtractParamsFromURLs scans a list of URLs and returns a deduplicated,
// sorted slice of all unique parameter key names found across all URLs.
func ExtractParamsFromURLs(urls []string) []string {
	seen := make(map[string]bool)
	for _, u := range urls {
		for _, k := range ExtractParamsFromURL(u) {
			seen[k] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FilterURLsWithParams returns only URLs that contain at least one query parameter.
func FilterURLsWithParams(urls []string) []string {
	var out []string
	for _, u := range urls {
		if strings.Contains(u, "?") && strings.Contains(u, "=") {
			out = append(out, u)
		}
	}
	return out
}

// DedupeParams returns a sorted, deduplicated slice of parameter keys.
func DedupeParams(params []string) []string {
	seen := make(map[string]bool, len(params))
	for _, p := range params {
		p = strings.TrimSpace(p)
		if p != "" {
			seen[p] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
