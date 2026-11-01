// Package inventory builds a standalone wildcard inventory report from the
// same scoped Store used by ReconX. No network requests are made here.
package inventory

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/scope"
	"github.com/unsocialz2/reconx/internal/store"
)

type HostRow struct {
	Wildcard   string   `json:"wildcard"`
	Subdomain  string   `json:"subdomain"`
	Status     string   `json:"status"`
	HTTP       []int    `json:"http_codes"`
	Endpoints  int      `json:"endpoints"`
	IP         string   `json:"ip"`
	Title      string   `json:"title"`
	Server     string   `json:"server"`
	Tech       []string `json:"technologies"`
	Priority   string   `json:"priority"`
	Score      int      `json:"score"`
	Reasons    []string `json:"reasons"`
	Screenshot string   `json:"screenshot,omitempty"`
}

type EndpointRow struct {
	Wildcard   string   `json:"wildcard"`
	Subdomain  string   `json:"subdomain"`
	URL        string   `json:"url"`
	Status     string   `json:"status"`
	Code       int      `json:"status_code"`
	IP         string   `json:"ip"`
	Title      string   `json:"title"`
	Server     string   `json:"server"`
	Tech       []string `json:"technologies"`
	Screenshot string   `json:"screenshot,omitempty"`
}

type Report struct {
	Disclaimer string        `json:"disclaimer"`
	Wildcards  []string      `json:"wildcards"`
	Hosts      []HostRow     `json:"hosts"`
	Endpoints  []EndpointRow `json:"endpoints"`
}

const disclaimer = "Scores rank analyst review only: not proven vulnerabilities, CVSS ratings, ownership or bounty eligibility. Verify third-party ownership and program rules before testing."

var statusNames = []string{"2xx", "3xx", "401-403", "404", "other-4xx", "429", "5xx", "unreachable"}
var priorityNames = []string{"P1", "P2", "P3", "P4", "Deferred"}

func status(code int) string {
	switch {
	case code >= 200 && code < 300: return "2xx"
	case code >= 300 && code < 400: return "3xx"
	case code == 401 || code == 403: return "401-403"
	case code == 404: return "404"
	case code == 429: return "429"
	case code >= 400 && code < 500: return "other-4xx"
	case code >= 500 && code < 600: return "5xx"
	default: return "unreachable"
	}
}
func statusRank(s string) int {
	switch s {
	case "2xx": return 8
	case "401-403": return 7
	case "3xx": return 6
	case "404": return 5
	case "other-4xx": return 4
	case "429": return 3
	case "5xx": return 2
	default: return 0
	}
}
func priority(score int, reachable bool) string {
	if !reachable { return "Deferred" }
	switch {
	case score >= 80: return "P1"
	case score >= 60: return "P2"
	case score >= 40: return "P3"
	default: return "P4"
	}
}

func wildcardLabel(a config.ScopeAsset) string {
	if a.Kind == "wildcard-origin" { return a.Scheme + "://*." + a.Host }
	return "*." + a.Host
}
func wildcardFor(host string, assets []config.ScopeAsset) string {
	var best config.ScopeAsset
	for _, a := range assets {
		if a.Excluded || (a.Kind != "wildcard" && a.Kind != "wildcard-origin") { continue }
		if host != a.Host && strings.HasSuffix(host, "."+a.Host) {
			if len(a.Host) > len(best.Host) || (len(a.Host) == len(best.Host) && wildcardLabel(a) < wildcardLabel(best)) {
				best = a
			}
		}
	}
	if best.Host == "" { return "" }
	return wildcardLabel(best)
}

func sortStrings(m map[string]bool) []string {
	s := make([]string, 0, len(m))
	for v := range m { s = append(s, v) }
	sort.Strings(s)
	return s
}

func urlOnly(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" { return "" }
	u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = "", false, "", ""
	if u.Path != "" && u.Path != "/" { u.Path = "/" }
	return u.String()
}

func scoreHost(h HostRow) (int, []string) {
	score := 10
	var reasons []string
	low := strings.ToLower(h.Subdomain)
	if contains(low, "admin.", "auth.", "sso.", "vpn.", "login.", "internal.", "console.") {
		score += 45
		reasons = append(reasons, "Management / identity naming signal")
	} else if contains(low, "api.", "graphql.", "portal.", "dev.", "staging.", "test.") {
		score += 28
		reasons = append(reasons, "API / portal / nonproduction naming signal")
	}
	tech := strings.ToLower(strings.Join(h.Tech, " "))
	if contains(tech, "jenkins", "gitlab", "grafana", "kibana", "jira", "drupal", "wordpress", "graphql", "swagger", "spring", "tomcat") {
		score += 15
		reasons = append(reasons, "Technology relevant to targeted manual review")
	}
	title := strings.ToLower(h.Title)
	if contains(title, "login", "admin", "dashboard", "sign in", "console") {
		score += 10
		reasons = append(reasons, "Page title suggests authentication or administration")
	}
	switch h.Status {
	case "2xx":
		score += 20
		reasons = append(reasons, "HTTP response: 2xx")
	case "401-403":
		score += 15
		reasons = append(reasons, "HTTP endpoint with authentication / access restriction")
	case "3xx":
		score += 10
		reasons = append(reasons, "Reachable redirect: check destination remains authorized")
	case "404", "other-4xx":
		score += 5
		reasons = append(reasons, "Reachable HTTP endpoint")
	case "429", "5xx":
		reasons = append(reasons, "Rate-limited or error response; defer active review")
	default:
		reasons = append(reasons, "Discovered name only; no confirmed HTTP response")
	}
	if h.Endpoints > 1 && h.Status != "unreachable" {
		score += 5
		reasons = append(reasons, "Multiple observed HTTP origins")
	}
	if score > 100 { score = 100 }
	return score, reasons
}
func contains(s string, needles ...string) bool {
	for _, n := range needles { if strings.Contains(s,n) { return true } }
	return false
}
func hostSafe(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
func imagePath(p string) string {
	if !strings.HasPrefix(p, "screenshots/inventory/") || !strings.HasSuffix(p, "/screenshot.png") || strings.Contains(p, "..") {
		return ""
	}
	return "../" + p
}

func Build(snap store.Snapshot, imported *config.ScopeImport, screenshots map[string]string) Report {
	result := Report{Disclaimer: disclaimer}
	if imported == nil { return result }
	cfg := config.DefaultConfig()
	cfg.Scope.Imported = imported
	filter := scope.New(cfg)
	for _, a := range imported.Assets {
		if !a.Excluded && (a.Kind == "wildcard" || a.Kind == "wildcard-origin") {
			result.Wildcards = append(result.Wildcards, wildcardLabel(a))
		}
	}
	sort.Strings(result.Wildcards)
	result.Wildcards = uniqueStrings(result.Wildcards)

	hosts := map[string]*HostRow{}
	get := func(host string) *HostRow {
		host = hostSafe(host)
		if host == "" || !filter.IsInScope(host) { return nil }
		group := wildcardFor(host, imported.Assets)
		if group == "" { return nil }
		h := hosts[host]
		if h == nil {
			h = &HostRow{Wildcard: group, Subdomain: host, Status: "unreachable"}
			hosts[host] = h
		}
		return h
	}
	for _, host := range snap.Subdomains { get(host) }
	type endpointSeen struct{ host string; code int }
	seen := map[string]endpointSeen{}
	for _, h := range snap.Hosts {
		if h == nil { continue }
		raw := ""
		if h.Meta != nil { raw = h.Meta["url"] }
		if raw == "" || !filter.IsInScope(raw) { continue }
		u, err := url.Parse(raw)
		if err != nil || u.User != nil { continue }
		a := get(u.Hostname())
		if a == nil { continue }
		raw = urlOnly(raw)
		if raw == "" { continue }
		row := EndpointRow{
			Wildcard: a.Wildcard, Subdomain: a.Subdomain, URL: raw,
			Code: h.StatusCode, Status: status(h.StatusCode), IP: h.IP,
			Title: h.Title, Server: h.Server, Tech: uniqueStrings(h.TechStack),
			Screenshot: imagePath(screenshots[raw]),
		}
		if prev, ok := seen[raw]; ok && prev.code == row.Code { continue }
		seen[raw] = endpointSeen{a.Subdomain, row.Code}
		result.Endpoints = append(result.Endpoints, row)
		a.Endpoints++
		a.HTTP = append(a.HTTP, row.Code)
		if statusRank(row.Status) > statusRank(a.Status) {
			a.Status = row.Status
			a.IP, a.Title, a.Server = row.IP, row.Title, row.Server
			a.Screenshot = row.Screenshot
		}
		if a.Screenshot == "" && row.Screenshot != "" { a.Screenshot = row.Screenshot }
		a.Tech = uniqueStrings(append(a.Tech, row.Tech...))
	}
	for _, h := range hosts {
		h.Score, h.Reasons = scoreHost(*h)
		h.Priority = priority(h.Score, statusRank(h.Status) >= 4)
		h.HTTP = uniqueInts(h.HTTP)
		result.Hosts = append(result.Hosts, *h)
	}
	sort.Slice(result.Hosts, func(i,j int) bool {
		a,b:=result.Hosts[i],result.Hosts[j]
		if a.Priority == "Deferred" && b.Priority != "Deferred" {return false}
		if a.Priority != "Deferred" && b.Priority == "Deferred" {return true}
		if a.Score != b.Score {return a.Score > b.Score}
		return a.Subdomain < b.Subdomain
	})
	sort.Slice(result.Endpoints,func(i,j int)bool{
		a,b:=result.Endpoints[i],result.Endpoints[j]
		if a.Wildcard != b.Wildcard{return a.Wildcard < b.Wildcard}
		if a.Subdomain != b.Subdomain{return a.Subdomain < b.Subdomain}
		return a.URL < b.URL
	})
	return result
}

func uniqueInts(in []int) []int {
	set:=map[int]bool{}
	for _,v:=range in{set[v]=true}
	out:=make([]int,0,len(set))
	for v:=range set{out=append(out,v)}
	sort.Ints(out)
	return out
}
func uniqueStrings(in []string) []string {
	set:=map[string]bool{}
	for _,v:=range in{if v!=""{set[v]=true}}
	return sortStrings(set)
}
func csvWrite(file string, header []string, rows [][]string) error {
	var b strings.Builder
	writer:=csv.NewWriter(&b)
	if err:=writer.Write(header);err!=nil{return err}
	for _,r:=range rows {if err:=writer.Write(r);err!=nil{return err}}
	writer.Flush()
	if err:=writer.Error();err!=nil{return err}
	return store.AtomicWrite(file,[]byte(b.String()),0600)
}
func hostCSV(h []HostRow) [][]string {
	rows:=make([][]string,0,len(h))
	for _,v:=range h {
		var codes []string
		for _,code:=range v.HTTP {codes=append(codes,strconv.Itoa(code))}
		rows=append(rows,[]string{v.Wildcard,v.Subdomain,v.Priority,strconv.Itoa(v.Score),v.Status,strings.Join(codes,","),strconv.Itoa(v.Endpoints),v.IP,v.Title,v.Server,strings.Join(v.Tech,"; "),v.Screenshot,strings.Join(v.Reasons,"; ")})
	}
	return rows
}
var hostHeaders=[]string{"wildcard","subdomain","priority","score","status_group","http_codes","endpoints","ip","title","server","technologies","screenshot","reasons"}
func endpointCSV(e []EndpointRow) [][]string {
	rows:=make([][]string,0,len(e))
	for _,v:=range e {
		rows=append(rows,[]string{v.Wildcard,v.Subdomain,v.URL,v.Status,strconv.Itoa(v.Code),v.IP,v.Title,v.Server,strings.Join(v.Tech,"; "),v.Screenshot})
	}
	return rows
}
var endpointHeaders=[]string{"wildcard","subdomain","url","status_group","http_code","ip","title","server","technologies","screenshot"}

func slug(wildcard string) string {
	var out strings.Builder
	for _,r:=range wildcard{
		if (r>='a'&&r<='z')||(r>='0'&&r<='9')||r=='-' {out.WriteRune(r)} else {out.WriteByte('_')}
	}
	return out.String()
}

func Generate(snap store.Snapshot, imported *config.ScopeImport, outDir string) error {
	if imported == nil { return fmt.Errorf("inventory requires imported wildcard scope") }
	shots := map[string]string{}
	if data,err:=os.ReadFile(filepath.Join(outDir,"screenshots","inventory_manifest.json"));err==nil{
		var rows []struct {URL string `json:"url"`; Path string `json:"path"`; Status string `json:"status"`}
		if json.Unmarshal(data,&rows)==nil{
			for _,item:=range rows{if item.Status=="captured"{shots[urlOnly(item.URL)]=item.Path}}
		}
	}
	report:=Build(snap,imported,shots)
	dest:=filepath.Join(outDir,"inventory")
	if len(report.Wildcards)==0 {return fmt.Errorf("no permitted wildcard entries available")}
	if err:=csvWrite(filepath.Join(dest,"subdomains_ranked.csv"),hostHeaders,hostCSV(report.Hosts));err!=nil{return err}
	if err:=csvWrite(filepath.Join(dest,"endpoints.csv"),endpointHeaders,endpointCSV(report.Endpoints));err!=nil{return err}
	encoded,err:=json.MarshalIndent(report,"","  ")
	if err!=nil{return err}
	if err:=store.AtomicWrite(filepath.Join(dest,"report.json"),encoded,0600);err!=nil{return err}
	for _,wc:=range report.Wildcards {
		var these []HostRow
		for _,h:=range report.Hosts{if h.Wildcard==wc{these=append(these,h)}}
		root:=filepath.Join(dest,"per_wildcard",slug(wc))
		if err:=csvWrite(filepath.Join(root,"subdomains_ranked.csv"),hostHeaders,hostCSV(these));err!=nil{return err}
		for _,st:=range statusNames{
			var found []HostRow
			for _,h:=range these{if h.Status==st{found=append(found,h)}}
			if err:=csvWrite(filepath.Join(root,"by_status",st+".csv"),hostHeaders,hostCSV(found));err!=nil{return err}
		}
		for _,p:=range priorityNames{
			var found []HostRow
			for _,h:=range these{if h.Priority==p{found=append(found,h)}}
			if err:=csvWrite(filepath.Join(root,"by_priority",p+".csv"),hostHeaders,hostCSV(found));err!=nil{return err}
		}
	}
	return renderHTML(filepath.Join(dest,"index.html"),report)
}

const page=`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ReconX | Wildcard Inventory</title><style>
:root{font:14px system-ui, sans-serif;color-scheme:dark}body{background:#0c121d;color:#e8edf7;margin:0 auto;padding:2rem;max-width:1550px}header{display:flex;align-items:center;justify-content:space-between;gap:2rem;flex-wrap:wrap}h1{font-size:1.8rem;margin:.3rem 0}p{color:#aebfd0;max-width:900px}select,input{background:#192537;color:#fff;border:1px solid #344660;border-radius:8px;padding:.65rem;min-width:150px}nav{display:flex;gap:.8rem;flex-wrap:wrap;margin:1.5rem 0}a{color:#7dd3fc}table{width:100%;border-collapse:collapse}th,td{padding:11px;border-bottom:1px solid #2a374b;text-align:left;vertical-align:top}th{position:sticky;top:0;background:#172132}tr:hover{background:#162236}td{max-width:300px;overflow-wrap:anywhere}img{display:block;max-width:180px;max-height:110px;border:1px solid #4e637c;border-radius:6px;object-fit:contain}small{color:#b6c6d8}code{color:#b7eeec}.filters{display:flex;gap:1rem;flex-wrap:wrap;align-items:center;margin:1rem 0}.p1{color:#ff9494}.p2{color:#ffbf77}.p3{color:#f6e28c}.p4{color:#8de8b2}.deferred{color:#8294a9}.tablebox{overflow:auto;border-radius:12px;border:1px solid #30405b}.muted{opacity:.75}.stats{display:flex;gap:1rem;flex-wrap:wrap}.stats div{padding:.8rem;background:#152033;border-radius:8px}#shown{font-weight:bold}
</style></head><body><header><div><small>ReconX / native inventory mode</small><h1>Wildcard Surface Inventory</h1><p>{{.Disclaimer}}</p></div><div class="stats"><div><b>{{len .Wildcards}}</b><br><small>Wildcards</small></div><div><b>{{len .Hosts}}</b><br><small>Subdomains</small></div><div><b>{{len .Endpoints}}</b><br><small>HTTP origins</small></div></div></header>
<nav><a href="subdomains_ranked.csv">Ranked CSV</a><a href="endpoints.csv">Endpoints CSV</a><a href="report.json">JSON</a></nav>
<div class="filters"><label>Wildcard <select id="wild"><option value="">All wildcards</option>{{range .Wildcards}}<option value="{{.}}">{{.}}</option>{{end}}</select></label>
<label>Status <select id="status"><option value="">All statuses</option>{{range .Statuses}}<option value="{{.}}">{{.}}</option>{{end}}</select></label>
<label>Priority <select id="priority"><option value="">All priorities</option>{{range .Priorities}}<option value="{{.}}">{{.}}</option>{{end}}</select></label>
<label>Search <input id="query" type="search" placeholder="subdomain, server, tech..."></label>
<span id="shown"></span></div>
<div class="tablebox"><table><thead><tr><th>Priority / score</th><th>Wildcard</th><th>Subdomain</th><th>HTTP status</th><th>IP / server</th><th>Technologies</th><th>Page title</th><th>Screenshot</th><th>Why review?</th></tr></thead><tbody>
{{range .Hosts}}<tr data-wild="{{.Wildcard}}" data-status="{{.Status}}" data-priority="{{.Priority}}"><td class="{{priorityClass .Priority}}"><b>{{.Priority}}</b> / {{.Score}}</td><td>{{.Wildcard}}</td><td><code>{{.Subdomain}}</code><small> ({{.Endpoints}} origins)</small></td><td>{{.Status}}<small>{{range .HTTP}} {{.}}{{end}}</small></td><td>{{.IP}}<small> {{.Server}}</small></td><td>{{range .Tech}}<small>{{.}} </small>{{end}}</td><td>{{.Title}}</td><td>{{if .Screenshot}}<a href="{{.Screenshot}}" target="_blank" rel="noopener"><img loading="lazy" alt="Screenshot" src="{{.Screenshot}}"></a>{{else}}<small>Not captured</small>{{end}}</td><td><small>{{range .Reasons}}{{.}}; {{end}}</small></td></tr>{{end}}
</tbody></table></div>
<script>
const filters=['wild','status','priority'].map(id=>document.getElementById(id)),query=document.getElementById('query'),rows=Array.from(document.querySelectorAll('tbody tr')),shown=document.getElementById('shown');
function apply(){let n=0;for(const row of rows){const ok=(!filters[0].value||row.dataset.wild===filters[0].value)&&(!filters[1].value||row.dataset.status===filters[1].value)&&(!filters[2].value||row.dataset.priority===filters[2].value)&&row.textContent.toLowerCase().includes(query.value.toLowerCase());row.hidden=!ok;if(ok)n++}shown.textContent=n+' / '+rows.length+' subdomains'}
for(const f of filters)f.addEventListener('change',apply);query.addEventListener('input',apply);apply();
</script></body></html>`

type pageData struct {
	Report
	Statuses []string
	Priorities []string
}
func renderHTML(path string,r Report)error{
	funcs:=template.FuncMap{"priorityClass":func(p string)string{return strings.ToLower(p)}}
	t,err:=template.New("inventory").Funcs(funcs).Parse(page)
	if err!=nil{return err}
	var body strings.Builder
	data:=pageData{Report:r,Statuses:statusNames,Priorities:priorityNames}
	if err:=t.Execute(&body,data);err!=nil{return err}
	return store.AtomicWrite(path,[]byte(body.String()),0600)
}
