package portscan

import (
        "context"
        "fmt"
        "strconv"
        "strings"
        "time"

        "github.com/reconx/reconx/internal/config"
        "github.com/reconx/reconx/internal/store"
        "github.com/reconx/reconx/pkg/logger"
        "github.com/reconx/reconx/pkg/runner"
        "github.com/reconx/reconx/pkg/util"
)

type Module struct {
        cfg    *config.Config
        store  *store.Store
        log    *logger.Logger
        outDir string
}

func New(cfg *config.Config, st *store.Store, log *logger.Logger, outDir string) *Module {
        return &Module{cfg: cfg, store: st, log: log, outDir: outDir}
}

func (m *Module) Run(ctx context.Context) error {
        m.log.Phase("Port Scanning", "Discovering open ports on all live hosts via naabu")

        start := time.Now()
        hosts := m.store.GetHosts()
        if len(hosts) == 0 {
                m.log.Warn("No live hosts to scan — alive check phase found nothing")
                return nil
        }

        tcfg := m.cfg.Tools["naabu"]
        naabuPath := "naabu"
        if tcfg.Path != "" {
                naabuPath = tcfg.Path
        }

        if !runner.IsAvailable(naabuPath) {
                m.log.ToolSkipped("naabu",
                        fmt.Sprintf("binary '%s' not found — install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", naabuPath))
                return nil
        }

        m.log.Debug("naabu version: %s (path: %s)", runner.Version(naabuPath), runner.WhichPath(naabuPath))

        // Build host list
        hostList := make([]string, 0, len(hosts))
        for _, h := range hosts {
                hostList = append(hostList, h.Domain)
        }
        input := strings.Join(hostList, "\n")

        // Base args — use -top-ports 1000 for naabu v2
        args := []string{"-json", "-silent", "-top-ports", "1000"}
        // Merge in user-configured flags (e.g. -rate 2000).
        args = append(args, tcfg.Flags...)
        m.log.Tool("naabu", fmt.Sprintf("%d live hosts", len(hostList)))
        m.log.ToolCmd("naabu", args, fmt.Sprintf("[%d hosts via stdin]", len(hostList)))

        portCount := 0
        parseErrors := 0

        r := runner.Run(ctx, naabuPath, args,
                runner.WithStdin(input),
                runner.WithTimeout(time.Duration(tcfg.Timeout)*time.Second),
                runner.WithStderrCallback(func(line string) {
                        // naabu writes progress to stderr — log at debug level
                        m.log.Debug("naabu: %s", line)
                }),
                runner.WithLineCallback(func(line string) {
                        line = strings.TrimSpace(line)
                        if line == "" {
                                return
                        }
                        p := parseNaabuLine(line)
                        if p == nil {
                                parseErrors++
                                m.log.Debug("naabu: failed to parse line: %s", util.Truncate(line, 100))
                                return
                        }
                        m.store.AddPort(p)
                        portCount++
                        m.log.Debug("open port: %s:%d (%s)", p.Host, p.Port, p.Service)
                }))

        if r.IsTimeout() {
                m.log.ToolTimeout("naabu", portCount, time.Duration(tcfg.Timeout)*time.Second)
        } else if r.Err != nil && portCount == 0 {
                m.log.ToolError("naabu", fmt.Errorf(r.DiagString()), r.Stderr)
                m.log.Warn("naabu returned 0 open ports — possible causes:")
                m.log.Warn("  1. All hosts are firewalled (common for cloud environments)")
                m.log.Warn("  2. naabu requires root/CAP_NET_RAW for SYN scan — try running as root")
                m.log.Warn("  3. Rate limit too high — reduce with -rate flag in config")
        } else {
                m.log.ToolDone("naabu", portCount, time.Since(start))
        }

        if parseErrors > 0 {
                m.log.Warn("naabu: %d lines could not be parsed — check reconx.log", parseErrors)
        }

        // Save ports.txt for resume support and downstream tools (ffuf, etc.)
        if portCount > 0 {
                portLines := make([]string, 0, len(m.store.Ports))
                for _, p := range m.store.Ports {
                        portLines = append(portLines, fmt.Sprintf("%s:%d", p.Host, p.Port))
                }
                if err := store.SaveRaw(m.outDir+"/ports.txt", portLines); err != nil {
                        m.log.Warn("Failed to save ports.txt: %v", err)
                } else {
                        m.log.Debug("Saved ports.txt (%d entries)", len(portLines))
                }
                m.logPortSummary()
        }

        m.log.PhaseComplete("Port Scanning", portCount, time.Since(start))
        return nil
}

func (m *Module) logPortSummary() {
        portCounts := make(map[int]int)
        for _, p := range m.store.Ports {
                portCounts[p.Port]++
        }

        interesting := []int{21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017}
        var found []string
        for _, port := range interesting {
                if c := portCounts[port]; c > 0 {
                        svc := guessService(port)
                        found = append(found, fmt.Sprintf("%d/%s(%d)", port, svc, c))
                }
        }
        if len(found) > 0 {
                m.log.Info("Interesting ports: %s", strings.Join(found, "  "))
        }
}

func parseNaabuLine(line string) *store.Port {
        // Try JSON format first: {"ip":"1.2.3.4","port":80,"host":"example.com"}
        if strings.HasPrefix(line, "{") {
                host := util.JsonStr(line, "host")
                if host == "" {
                        host = util.JsonStr(line, "ip")
                }
                portStr := util.JsonStr(line, "port")
                port, err := strconv.Atoi(portStr)
                if err != nil || port == 0 {
                        return nil
                }
                if host == "" {
                        return nil
                }
                return &store.Port{
                        Host:     host,
                        Port:     port,
                        Protocol: "tcp",
                        Service:  guessService(port),
                }
        }

        // Plain text format: host:port
        if idx := strings.LastIndex(line, ":"); idx > 0 {
                portStr := strings.TrimSpace(line[idx+1:])
                port, err := strconv.Atoi(portStr)
                if err != nil || port == 0 || port > 65535 {
                        return nil
                }
                host := strings.TrimSpace(line[:idx])
                return &store.Port{
                        Host:     host,
                        Port:     port,
                        Protocol: "tcp",
                        Service:  guessService(port),
                }
        }
        return nil
}

func guessService(port int) string {
        services := map[int]string{
                21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
                80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
                587: "smtp-tls", 993: "imaps", 995: "pop3s",
                1433: "mssql", 3306: "mysql", 3389: "rdp",
                5432: "postgres", 5900: "vnc", 6379: "redis",
                8080: "http-alt", 8443: "https-alt", 8888: "jupyter",
                9200: "elasticsearch", 27017: "mongodb",
        }
        if s, ok := services[port]; ok {
                return s
        }
        return "unknown"
}


