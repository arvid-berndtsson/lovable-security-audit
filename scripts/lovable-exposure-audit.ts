#!/usr/bin/env bun

type Options = {
  targetsFile?: string;
  outputDir: string;
  timeoutMs: number;
  concurrency: number;
  includePaths: string[];
  apiBaseUrl?: string;
  apiProjectsPath: string;
  apiToken?: string;
};

type HttpResult = {
  url: string;
  status?: number;
  ok: boolean;
  contentType?: string;
  snippet?: string;
  error?: string;
};

type RawFetchResult = {
  url: string;
  status?: number;
  ok: boolean;
  contentType?: string;
  text?: string;
  error?: string;
};

type PathFinding = {
  path: string;
  severity: "high" | "medium" | "low" | "none";
  reason: string;
  result: HttpResult;
};

type TargetReport = {
  target: string;
  homepage: HttpResult;
  findings: PathFinding[];
};

const DEFAULT_PATHS = [
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.git/HEAD",
  "/.git/config",
  "/.git/index",
  "/.git/logs/HEAD"
];

function printHelp() {
  console.log(`
Lovable exposure audit (defensive)

Usage:
  bun run scripts/lovable-exposure-audit.ts [options]

Options:
  --targets-file <path>      Text file containing one app URL per line
  --output-dir <path>        Report directory (default: reports)
  --timeout-ms <number>      HTTP timeout per request (default: 12000)
  --concurrency <number>     Parallel target scans (default: 6)
  --paths <csv>              Override tested paths
  --api-base-url <url>       Optional API base URL for project discovery
  --api-projects-path <path> Optional API projects endpoint path (default: /v1/projects)
  --api-token <token>        Optional bearer token for API discovery
  --help                     Show help

Environment variables (alternative to flags):
  LOVABLE_TARGETS_FILE
  LOVABLE_AUDIT_OUTPUT_DIR
  LOVABLE_AUDIT_TIMEOUT_MS
  LOVABLE_AUDIT_CONCURRENCY
  LOVABLE_AUDIT_PATHS
  LOVABLE_API_BASE_URL
  LOVABLE_API_PROJECTS_PATH
  LOVABLE_API_TOKEN
  LOVABLE_PROJECT_URLS      Comma-separated list of app URLs
`);
}

function parseArgs(argv: string[]): Options {
  const opts: Options = {
    targetsFile: process.env.LOVABLE_TARGETS_FILE,
    outputDir: process.env.LOVABLE_AUDIT_OUTPUT_DIR || "reports",
    timeoutMs: Number(process.env.LOVABLE_AUDIT_TIMEOUT_MS || "12000"),
    concurrency: Number(process.env.LOVABLE_AUDIT_CONCURRENCY || "6"),
    includePaths: (process.env.LOVABLE_AUDIT_PATHS || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    apiBaseUrl: process.env.LOVABLE_API_BASE_URL,
    apiProjectsPath: process.env.LOVABLE_API_PROJECTS_PATH || "/v1/projects",
    apiToken: process.env.LOVABLE_API_TOKEN
  };

  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    const value = argv[i + 1];
    if (key === "--help") {
      printHelp();
      process.exit(0);
    }
    if (key === "--targets-file" && value) {
      opts.targetsFile = value;
      i += 1;
      continue;
    }
    if (key === "--output-dir" && value) {
      opts.outputDir = value;
      i += 1;
      continue;
    }
    if (key === "--timeout-ms" && value) {
      opts.timeoutMs = Number(value);
      i += 1;
      continue;
    }
    if (key === "--concurrency" && value) {
      opts.concurrency = Number(value);
      i += 1;
      continue;
    }
    if (key === "--paths" && value) {
      opts.includePaths = value.split(",").map((s) => s.trim()).filter(Boolean);
      i += 1;
      continue;
    }
    if (key === "--api-base-url" && value) {
      opts.apiBaseUrl = value;
      i += 1;
      continue;
    }
    if (key === "--api-projects-path" && value) {
      opts.apiProjectsPath = value;
      i += 1;
      continue;
    }
    if (key === "--api-token" && value) {
      opts.apiToken = value;
      i += 1;
      continue;
    }
  }

  if (opts.includePaths.length === 0) {
    opts.includePaths = DEFAULT_PATHS;
  }
  if (!Number.isFinite(opts.timeoutMs) || opts.timeoutMs < 1000) {
    opts.timeoutMs = 12000;
  }
  if (!Number.isFinite(opts.concurrency) || opts.concurrency < 1) {
    opts.concurrency = 6;
  }
  return opts;
}

function normalizeUrl(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed || trimmed.startsWith("#")) {
    return null;
  }
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const url = new URL(withScheme);
    url.hash = "";
    url.search = "";
    return url.toString().replace(/\/$/, "");
  } catch {
    return null;
  }
}

async function readTargetsFile(path: string): Promise<string[]> {
  const file = Bun.file(path);
  if (!(await file.exists())) {
    console.warn(`Targets file not found: ${path}`);
    return [];
  }
  const text = await file.text();
  return text
    .split(/\r?\n/g)
    .map((line) => normalizeUrl(line))
    .filter((line): line is string => Boolean(line));
}

function projectUrlCandidates(project: Record<string, unknown>): string[] {
  const fields = [
    "publishedUrl",
    "published_url",
    "liveUrl",
    "live_url",
    "projectUrl",
    "project_url",
    "url",
    "customDomain",
    "domain"
  ];
  const values: string[] = [];
  for (const key of fields) {
    const raw = project[key];
    if (typeof raw === "string" && raw.trim()) {
      values.push(raw);
    }
  }
  return values;
}

function extractProjectUrls(payload: unknown): string[] {
  const urls = new Set<string>();
  const queue: unknown[] = [payload];
  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) {
      continue;
    }
    if (Array.isArray(current)) {
      queue.push(...current);
      continue;
    }
    if (typeof current === "object") {
      const record = current as Record<string, unknown>;
      for (const candidate of projectUrlCandidates(record)) {
        const normalized = normalizeUrl(candidate);
        if (normalized) {
          urls.add(normalized);
        }
      }
      for (const value of Object.values(record)) {
        if (typeof value === "object" && value !== null) {
          queue.push(value);
        }
      }
    }
  }
  return [...urls];
}

async function fetchApiTargets(opts: Options): Promise<string[]> {
  if (!opts.apiBaseUrl || !opts.apiToken) {
    return [];
  }
  const base = opts.apiBaseUrl.endsWith("/") ? opts.apiBaseUrl.slice(0, -1) : opts.apiBaseUrl;
  const path = opts.apiProjectsPath.startsWith("/") ? opts.apiProjectsPath : `/${opts.apiProjectsPath}`;
  const endpoint = `${base}${path}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs);
  try {
    const response = await fetch(endpoint, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${opts.apiToken}`,
        Accept: "application/json",
        "User-Agent": "lovable-security-audit/0.1"
      },
      signal: controller.signal
    });
    if (!response.ok) {
      const body = await response.text();
      console.warn(`API discovery request failed (${response.status}): ${endpoint}`);
      console.warn(`API response preview: ${body.slice(0, 300)}`);
      return [];
    }
    const json = await response.json();
    const urls = extractProjectUrls(json);
    console.log(`Discovered ${urls.length} project URL candidates via API`);
    return urls;
  } catch (error) {
    console.warn(`API discovery error: ${(error as Error).message}`);
    return [];
  } finally {
    clearTimeout(timeout);
  }
}

function redactSensitiveValues(text: string): string {
  return text
    .split(/\r?\n/g)
    .map((line) => {
      const match = line.match(/^([A-Za-z0-9_./-]{2,})\s*=\s*(.+)$/);
      if (!match) {
        return line;
      }
      const key = match[1];
      const value = match[2].trim();
      const sensitive = /(secret|token|password|pass|private|key|auth|credential)/i.test(key);
      if (!sensitive) {
        return `${key}=${value.slice(0, 6)}...`;
      }
      return `${key}=***REDACTED***`;
    })
    .join("\n")
    .replace(/(https?:\/\/[^:\s]+:)[^@\s]+@/gi, "$1***@");
}

function looksLikeEnv(body: string): boolean {
  const lines = body.split(/\r?\n/g).filter((line) => line.trim().length > 0);
  if (lines.length === 0) {
    return false;
  }
  const envLike = lines.filter((line) => /^[A-Za-z_][A-Za-z0-9_]*\s*=/.test(line.trim())).length;
  return envLike >= Math.max(1, Math.ceil(lines.length * 0.3));
}

function classifyFinding(path: string, result: HttpResult): Omit<PathFinding, "path" | "result"> {
  const status = result.status ?? 0;
  const snippet = result.snippet || "";
  const lowerSnippet = snippet.toLowerCase();
  const looksLikeHtmlFallback =
    lowerSnippet.includes("<!doctype html") || lowerSnippet.includes("<html");

  if (!result.ok) {
    return {
      severity: "none",
      reason: result.error || "Request failed"
    };
  }
  if ([401, 403, 404].includes(status)) {
    return {
      severity: "none",
      reason: `Access blocked (${status})`
    };
  }
  if (path.startsWith("/.env")) {
    if (status >= 200 && status < 300 && looksLikeHtmlFallback) {
      return {
        severity: "low",
        reason: "Returned HTML route fallback; sensitive file path did not return file contents"
      };
    }
    if (status === 200 && looksLikeEnv(snippet)) {
      return {
        severity: "high",
        reason: "Endpoint returned content that looks like environment variables"
      };
    }
    if (status >= 200 && status < 300) {
      return {
        severity: "medium",
        reason: "Endpoint unexpectedly reachable and should be blocked"
      };
    }
  }
  if (path === "/.git/HEAD" && status === 200 && /ref:\s*refs\//i.test(snippet)) {
    return {
      severity: "high",
      reason: "Git metadata exposed (.git/HEAD)"
    };
  }
  if (path === "/.git/config" && status === 200 && /\[(core|remote)\]/i.test(snippet)) {
    return {
      severity: "high",
      reason: "Git config exposed (.git/config)"
    };
  }
  if (path === "/.git/index" && status === 200) {
    if (looksLikeHtmlFallback) {
      return {
        severity: "low",
        reason: "Returned HTML route fallback; no git index signature detected"
      };
    }
    if (/DIRC/.test(snippet)) {
      return {
        severity: "high",
        reason: "Git index exposed (.git/index signature detected)"
      };
    }
    return {
      severity: "medium",
      reason: "Potential git index exposure (path reachable)"
    };
  }
  if (path === "/.git/logs/HEAD" && status === 200 && /[0-9a-f]{40}/i.test(snippet)) {
    return {
      severity: "high",
      reason: "Git commit history artifacts exposed (.git/logs/HEAD)"
    };
  }
  if (status >= 200 && status < 300 && looksLikeHtmlFallback) {
    return {
      severity: "low",
      reason: "Returned HTML route fallback; check routing and edge rules"
    };
  }
  if (status >= 200 && status < 300) {
    return {
      severity: "medium",
      reason: "Sensitive path is reachable"
    };
  }
  return {
    severity: "none",
    reason: `No direct exposure signal (status ${status})`
  };
}

async function fetchPreview(url: string, timeoutMs: number): Promise<HttpResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      redirect: "follow",
      headers: {
        "User-Agent": "lovable-security-audit/0.1"
      },
      signal: controller.signal
    });
    const contentType = response.headers.get("content-type") || undefined;
    const text = await response.text();
    const snippet = redactSensitiveValues(text.slice(0, 2000));
    return {
      url,
      status: response.status,
      ok: true,
      contentType,
      snippet
    };
  } catch (error) {
    return {
      url,
      ok: false,
      error: (error as Error).message
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchTextRaw(url: string, timeoutMs: number): Promise<RawFetchResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      redirect: "follow",
      headers: {
        "User-Agent": "lovable-security-audit/0.1"
      },
      signal: controller.signal
    });
    const contentType = response.headers.get("content-type") || undefined;
    const text = await response.text();
    return {
      url,
      status: response.status,
      ok: true,
      contentType,
      text
    };
  } catch (error) {
    return {
      url,
      ok: false,
      error: (error as Error).message
    };
  } finally {
    clearTimeout(timeout);
  }
}

function makeChildUrl(base: string, path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${base}${normalizedPath}`;
}

function titleFromHtml(text: string | undefined): string | undefined {
  if (!text) {
    return undefined;
  }
  const match = text.match(/<title[^>]*>([^<]*)<\/title>/i);
  if (!match) {
    return undefined;
  }
  return match[1].replace(/\s+/g, " ").trim();
}

function extractJsAssetPaths(html: string): string[] {
  const matches = html.match(/\/assets\/[A-Za-z0-9._/-]+\.js/g) || [];
  return [...new Set(matches)].slice(0, 8);
}

function maskToken(token: string): string {
  if (token.length <= 36) {
    return `${token.slice(0, 8)}...`;
  }
  return `${token.slice(0, 16)}...${token.slice(-8)}`;
}

function decodeJwtRole(token: string): string | null {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }
  const payload = parts[1];
  try {
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const normalized = b64.padEnd(Math.ceil(b64.length / 4) * 4, "=");
    const json = JSON.parse(Buffer.from(normalized, "base64").toString("utf8")) as Record<
      string,
      unknown
    >;
    return typeof json.role === "string" ? json.role : null;
  } catch {
    return null;
  }
}

function summarizeSupabaseBundleSnippet(
  domains: string[],
  tokenRoles: string[],
  tokens: string[],
  highMarkers: string[]
): string {
  const lines = [
    `supabase_domains=${domains.join(",") || "none"}`,
    `jwt_roles=${tokenRoles.join(",") || "none"}`,
    `jwt_samples=${tokens.slice(0, 2).map(maskToken).join(",") || "none"}`,
    `high_risk_markers=${highMarkers.join(",") || "none"}`
  ];
  return lines.join("\n");
}

async function scanBundleForSupabase(baseUrl: string, timeoutMs: number): Promise<PathFinding[]> {
  const homepage = await fetchTextRaw(baseUrl, timeoutMs);
  if (!homepage.ok || (homepage.status ?? 0) < 200 || (homepage.status ?? 0) >= 400 || !homepage.text) {
    return [];
  }

  const jsPaths = extractJsAssetPaths(homepage.text);
  if (jsPaths.length === 0) {
    return [];
  }

  const findings: PathFinding[] = [];
  for (const jsPath of jsPaths) {
    const assetUrl = makeChildUrl(baseUrl, jsPath);
    const asset = await fetchTextRaw(assetUrl, timeoutMs);
    if (!asset.ok || asset.status !== 200 || !asset.text) {
      continue;
    }

    const text = asset.text;
    const domains = [...new Set(text.match(/https:\/\/[a-z0-9-]+\.supabase\.co/g) || [])];
    const tokens = [...new Set(text.match(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g) || [])];
    const tokenRoles = [...new Set(tokens.map((token) => decodeJwtRole(token)).filter(Boolean) as string[])];
    const highMarkers = [
      ...new Set(
        text.match(
          /service_role|service-role|sb_secret_[A-Za-z0-9_-]+|postgres:\/\/[^\s"'`]+|sk-[A-Za-z0-9]{20,}/g
        ) || []
      )
    ];

    const hasSupabaseSignal = domains.length > 0 || tokenRoles.length > 0 || highMarkers.length > 0;
    if (!hasSupabaseSignal) {
      continue;
    }

    let severity: PathFinding["severity"] = "low";
    let reason = "Supabase public client configuration detected in bundle";

    const hasServiceRole = tokenRoles.includes("service_role") || highMarkers.some((m) => /service_role/i.test(m));
    const hasSecretMarkers = highMarkers.some((m) => /^sb_secret_|^postgres:\/\//.test(m) || /^sk-/.test(m));

    if (hasServiceRole || hasSecretMarkers) {
      severity = "high";
      reason = "Potential privileged secret detected in frontend bundle";
    } else if (tokenRoles.length > 0 && !tokenRoles.every((role) => role === "anon")) {
      severity = "medium";
      reason = "Non-anon Supabase JWT role found in frontend bundle";
    } else if (domains.length > 0 && tokens.length > 0 && tokenRoles.includes("anon")) {
      severity = "low";
      reason = "Supabase URL + anon key present in frontend bundle (typical; validate RLS)"
    }

    findings.push({
      path: `bundle:${jsPath}`,
      severity,
      reason,
      result: {
        url: assetUrl,
        status: asset.status,
        ok: true,
        contentType: asset.contentType,
        snippet: summarizeSupabaseBundleSnippet(domains, tokenRoles, tokens, highMarkers)
      }
    });
  }

  return findings;
}

async function auditTarget(target: string, opts: Options): Promise<TargetReport> {
  const homepage = await fetchPreview(target, opts.timeoutMs);
  const findings: PathFinding[] = [];
  for (const path of opts.includePaths) {
    const result = await fetchPreview(makeChildUrl(target, path), opts.timeoutMs);
    const classification = classifyFinding(path, result);
    findings.push({
      path,
      severity: classification.severity,
      reason: classification.reason,
      result
    });
  }
  const bundleFindings = await scanBundleForSupabase(target, opts.timeoutMs);
  findings.push(...bundleFindings);
  return {
    target,
    homepage: {
      ...homepage,
      snippet: titleFromHtml(homepage.snippet)
    },
    findings
  };
}

async function runWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let index = 0;
  async function worker() {
    while (true) {
      const current = index;
      index += 1;
      if (current >= items.length) {
        return;
      }
      results[current] = await fn(items[current], current);
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

function severityCount(reports: TargetReport[], level: "high" | "medium" | "low"): number {
  return reports
    .flatMap((report) => report.findings)
    .filter((finding) => finding.severity === level).length;
}

function buildMarkdownReport(
  reports: TargetReport[],
  opts: Options,
  sources: { fileCount: number; envCount: number; apiCount: number }
): string {
  const rows = reports
    .map((report) => {
      const high = report.findings.filter((f) => f.severity === "high").length;
      const medium = report.findings.filter((f) => f.severity === "medium").length;
      const low = report.findings.filter((f) => f.severity === "low").length;
      const homepageStatus = report.homepage.status ?? "ERR";
      const homepageTitle = report.homepage.snippet || "";
      return `| ${report.target} | ${homepageStatus} | ${high} | ${medium} | ${low} | ${homepageTitle
        .replace(/\\/g, "\\\\")
        .replace(/\|/g, "\\|")} |`;
    })
    .join("\n");

  const findings = reports
    .flatMap((report) =>
      report.findings
        .filter((finding) => finding.severity === "high" || finding.severity === "medium")
        .map((finding) => {
          const status = finding.result.status ?? "ERR";
          return [
            `### ${finding.severity.toUpperCase()} ${report.target}${finding.path}`,
            `- Reason: ${finding.reason}`,
            `- HTTP status: ${status}`,
            `- URL: ${finding.result.url}`,
            "```txt",
            finding.result.snippet || "(no response snippet)",
            "```"
          ].join("\n");
        })
    )
    .join("\n\n");

  return [
    "# Lovable Hosted App Exposure Audit",
    "",
    `- Scanned targets: ${reports.length}`,
    `- Sources: file=${sources.fileCount}, env=${sources.envCount}, api=${sources.apiCount}`,
    `- Paths tested: ${opts.includePaths.join(", ")}`,
    `- High findings: ${severityCount(reports, "high")}`,
    `- Medium findings: ${severityCount(reports, "medium")}`,
    `- Low findings: ${severityCount(reports, "low")}`,
    "",
    "## Target Summary",
    "",
    "| Target | Homepage | High | Medium | Low | Homepage title |",
    "|---|---:|---:|---:|---:|---|",
    rows,
    "",
    "## Evidence (high/medium)",
    "",
    findings || "No high/medium findings detected.",
    ""
  ].join("\n");
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const envTargets = (process.env.LOVABLE_PROJECT_URLS || "")
    .split(",")
    .map((item) => normalizeUrl(item))
    .filter((item): item is string => Boolean(item));
  const fileTargets = opts.targetsFile ? await readTargetsFile(opts.targetsFile) : [];
  const apiTargets = await fetchApiTargets(opts);
  const targets = [...new Set([...fileTargets, ...envTargets, ...apiTargets])];

  if (targets.length === 0) {
    console.error("No targets found. Provide --targets-file and/or LOVABLE_PROJECT_URLS.");
    process.exit(1);
  }

  console.log(`Starting scan for ${targets.length} targets with concurrency=${opts.concurrency}`);
  const reports = await runWithConcurrency(targets, opts.concurrency, (target, i) => {
    console.log(`[${i + 1}/${targets.length}] ${target}`);
    return auditTarget(target, opts);
  });

  await Bun.$`mkdir -p ${opts.outputDir}`;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const jsonPath = `${opts.outputDir}/lovable-exposure-${stamp}.json`;
  const mdPath = `${opts.outputDir}/lovable-exposure-${stamp}.md`;

  const summary = {
    generatedAt: new Date().toISOString(),
    options: opts,
    summary: {
      targets: reports.length,
      high: severityCount(reports, "high"),
      medium: severityCount(reports, "medium"),
      low: severityCount(reports, "low")
    },
    reports
  };

  await Bun.write(jsonPath, JSON.stringify(summary, null, 2));
  await Bun.write(
    mdPath,
    buildMarkdownReport(reports, opts, {
      fileCount: fileTargets.length,
      envCount: envTargets.length,
      apiCount: apiTargets.length
    })
  );

  console.log(`JSON report: ${jsonPath}`);
  console.log(`Markdown report: ${mdPath}`);

  if (summary.summary.high > 0 || summary.summary.medium > 0) {
    process.exitCode = 2;
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
