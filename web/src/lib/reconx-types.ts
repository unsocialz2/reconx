export type ViewMode = 'new-scan' | 'history' | 'progress' | 'results' | 'guide';
export type PhaseKey = 'subs' | 'alive' | 'ports' | 'urls' | 'dirs' | 'params' | 'js' | 'cloud' | 'cors' | 'vuln';

export interface SavedSettings {
  githubToken?: string;
  chaosKey?: string;
  shodanKey?: string;
  virustotalKey?: string;
  securitytrailsKey?: string;
  orgName?: string;
  customHeader?: string;
  outputDir?: string;
  verbose?: boolean;
  noTimeout?: boolean;
  htmlReport?: boolean;
  jsonReport?: boolean;
  saveRaw?: boolean;
  workers?: number;
}

export interface ScanConfig {
  domains: string[];
  ipRanges?: string[];
  asns?: string[];
  orgName?: string;
  scopeIn?: string[];
  scopeOut?: string[];
  header?: string;
  wordlist?: string;
  resolvers?: string[];
  skipSubs?: boolean;
  skipAlive?: boolean;
  skipPorts?: boolean;
  skipUrls?: boolean;
  skipJs?: boolean;
  skipVuln?: boolean;
  enableFuzz?: boolean;
  enableParams?: boolean;
  skipCloud?: boolean;
  skipCors?: boolean;
  noTimeout?: boolean;
  tokens?: {
    github?: string;
    chaos?: string;
    shodan?: string;
    virustotal?: string;
    securitytrails?: string;
  };
}

export interface ScanMetadata {
  id: string;
  domains: string[];
  ipRanges?: string[];
  asns?: string[];
  orgName?: string;
  startTime: string;
  endTime?: string;
  status: 'running' | 'completed' | 'failed' | 'stopped';
  outputDir: string;
  pid?: number;
  config?: ScanConfig;
  stats?: Record<string, number>;
}

export interface SubdomainSourceEntry {
  subdomain: string;
  source: string;
}

export interface HostEntry {
  domain: string;
  ip?: string;
  status_code?: number;
  title?: string;
  server?: string;
  port?: number;
  tech_stack?: string[];
  tags?: string[];
  meta?: Record<string, string>;
}

export interface PortEntry {
  host: string;
  port: number;
  protocol: string;
  service?: string;
  banner?: string;
}

export interface VulnEntry {
  name: string;
  severity: string;
  target: string;
  description?: string;
  evidence?: string;
  template?: string;
  found_at: string;
}

export interface SecretEntry {
  type: string;
  value: string;
  source: string;
  file?: string;
}

export interface DirEntry {
  url: string;
  status_code: number;
  size?: number;
  tool: string;
  target: string;
}

export interface WAFEntry {
  host: string;
  waf: string;
  detected: boolean;
}

export interface CloudEntry {
  provider: string;
  name: string;
  url: string;
  status: string;
  accessible: boolean;
}

export interface CORSEntry {
  url: string;
  origin: string;
  acao: string;
  acac: string;
  severity: string;
  description: string;
}

export interface ParamEntry {
  url: string;
  method: string;
  params: string[];
  tool: string;
}

export interface ScanResult {
  scan_id?: string;
  start_time?: string;
  duration?: string;
  subdomains?: string[];
  subdomain_sources?: SubdomainSourceEntry[];
  hosts?: HostEntry[];
  ports?: PortEntry[];
  urls?: string[];
  findings?: VulnEntry[];
  secrets?: SecretEntry[];
  dir_results?: DirEntry[];
  waf_results?: WAFEntry[];
  cloud_assets?: CloudEntry[];
  cors_results?: CORSEntry[];
  param_results?: ParamEntry[];
}
