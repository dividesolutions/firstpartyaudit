import {
  chromium,
  type Browser,
  type Request,
  type Response,
} from "playwright";
import { parse as parseTld } from "tldts";

/**
 * First-Party Site Scanner (tracking-first)
 *
 * New scoring model:
 * - 70%: Presence of ANY watched first-party subdomain request (e.g. fp/api/collect/etc.)
 * - 30%: Cookie presence across platforms (Meta / GA / Google Ads / TikTok)
 *
 * Hard rules:
 * - If NO watched subdomain requests are present, overall cannot exceed 30.
 * - Overall score is capped at 90 (100 is not possible).
 *
 * Cookie capture:
 * - Uses BOTH Set-Cookie headers AND context.cookies() (includes JS-set cookies).
 *
 * Output:
 * - Only returns cookies we care about (tracking cookies from known catalog / identifiers).
 * - Removes bulky/unused fields in the return payload.
 */

// -----------------------------
// Types
// -----------------------------
type Platform =
  | "Meta"
  | "Google Analytics"
  | "Google Ads"
  | "TikTok"
  | "LinkedIn"
  | "Unknown";
type Category = "Ads" | "Analytics";
type HostType = "root" | "firstPartySubdomain" | "thirdParty";
type Grade = "A" | "B" | "C" | "D" | "F";

type CookieRecord = {
  name: string;
  domain: string;
  path?: string;

  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;

  provider: Platform;
  category: Category;
  hostType: HostType;

  // derived
  isTracking: boolean;
  isFirstPartyTracking: boolean;
  isThirdPartyTracking: boolean;
};

type PlatformReport = {
  platform: Exclude<Platform, "Unknown">;
  score: number; // 0-90 (presence-only)
  present: boolean;
  resolveCTA: string;
  debug: {
    cookies: string[];
    fpCookies: string[];
    tpCookies: string[];
  };
};

type SubdomainCookieSetSignal = {
  responseUrl: string;
  responseHostname: string;
  subdomainLabel: string;
  cookieName: string;
  cookieDomain: string;
  path?: string;
  secure: boolean;
  httpOnly: boolean;
  maxAge?: number | null;
};

type AuditDebug = {
  notes: string[];
  loadMs: number;

  scoring: {
    watchedSubdomainPresent: boolean;
    watchedSubdomainHosts: string[];
    cookiePlatformsPresent: string[];
    watchedBucketScore: number; // 0..90 (but contributes 70% weight)
    cookieBucketScore: number; // 0..90 (but contributes 30% weight)
    overallCappedTo90: boolean;
  };
};

type AuditResult = {
  url: string;
  overallScore: number; // 0..90
  letterGrade: Grade;

  signals: {
    watchedSubdomainHosts: string[]; // presence signal (drives 70%)
    watchedSubdomainRootCookieSets: SubdomainCookieSetSignal[]; // useful diagnostic
  };

  recommendedActions: string;

  platforms: PlatformReport[];

  cookies: {
    tracking: CookieRecord[]; // ONLY cookies we care about
  };

  debug: AuditDebug;
};

// -----------------------------
// Cookie catalog + identifier rules
// -----------------------------
type CookieCatalogEntry = {
  provider: Exclude<Platform, "Unknown">;
  category: Category;
  match: (name: string) => boolean;
};

const COOKIE_CATALOG: CookieCatalogEntry[] = [
  // Meta
  { provider: "Meta", category: "Ads", match: (n) => n === "_fbp" },
  { provider: "Meta", category: "Ads", match: (n) => n === "_fbc" },

  // Google Analytics / GA4
  {
    provider: "Google Analytics",
    category: "Analytics",
    match: (n) => n === "_ga",
  },
  {
    provider: "Google Analytics",
    category: "Analytics",
    match: (n) => n.startsWith("_ga_"),
  },

  // Google Ads
  { provider: "Google Ads", category: "Ads", match: (n) => n === "_gcl_au" },
  {
    provider: "Google Ads",
    category: "Ads",
    match: (n) => n.toLowerCase() === "fpgclaw",
  },
  {
    provider: "Google Ads",
    category: "Ads",
    match: (n) => n.toLowerCase() === "fpid",
  },

  // TikTok
  { provider: "TikTok", category: "Ads", match: (n) => n === "_ttp" },

  // LinkedIn (Insight Tag / advertiser-side identifier)
  { provider: "LinkedIn", category: "Ads", match: (n) => n === "li_fat_id" },
  // Sometimes seen with LinkedIn tags / integrations
  { provider: "LinkedIn", category: "Ads", match: (n) => n === "_li_dcdm_c" },
];

function isKnownIdentifierCookieName(name: string): boolean {
  const n = name.toLowerCase();
  return (
    n === "_ga" ||
    n.startsWith("_ga_") ||
    n === "_fbp" ||
    n === "_fbc" ||
    n === "_gcl_au" ||
    n === "fpgclaw" ||
    n === "fpid" ||
    n === "_ttp" ||
    n === "li_fat_id" ||
    n === "_li_dcdm_c"
  );
}

function inferProviderFromName(name: string): {
  provider: Platform;
  category: Category;
} {
  const n = name.toLowerCase();

  if (n === "_fbp" || n === "_fbc")
    return { provider: "Meta", category: "Ads" };
  if (n === "_ttp") return { provider: "TikTok", category: "Ads" };
  if (n === "li_fat_id" || n === "_li_dcdm_c")
    return { provider: "LinkedIn", category: "Ads" };
  if (n === "_gcl_au") return { provider: "Google Ads", category: "Ads" };
  if (n === "_ga" || n.startsWith("_ga_"))
    return { provider: "Google Analytics", category: "Analytics" };
  if (n === "fpgclaw") return { provider: "Google Ads", category: "Ads" };

  if (n === "fpid") return { provider: "Google Ads", category: "Ads" };

  return { provider: "Unknown", category: "Analytics" };
}

// -----------------------------
// Watched subdomains
// -----------------------------
const WATCHED_SUBDOMAINS = new Set([
  "api",
  "app",
  "edge",
  "ingest",
  "log",
  "logs",
  "pipe",
  "pipe",
  "stream",
  "gtm",
  "sgtm",
  "ss",
  "ssgtm",
  "server",
  "server-gtm",
  "tag",
  "tags",
  "data",
  "events",
  "track",
  "tracking",
  "analytics",
  "metrics",
  "collect",
  "collector",
  "stats",
  "beacon",
  "pixel",
  "signals",
  "fp",
]);

// -----------------------------
// Public API
// -----------------------------
export async function runAudit(
  url: string,
  opts?: {
    timeoutMs?: number;
    twoPass?: boolean;
    syntheticClickIds?: boolean;
    headless?: boolean;
  },
): Promise<AuditResult> {
  const timeoutMs = opts?.timeoutMs ?? 45_000;
  const twoPass = opts?.twoPass ?? true;
  const syntheticClickIds = opts?.syntheticClickIds ?? true;
  const headless = opts?.headless ?? true;

  const notes: string[] = [];

  const browser = await chromium.launch({
    headless,
    args: ["--disable-blink-features=AutomationControlled"],
  });

  try {
    // Always include realistic click identifiers so sites that rely on them
    // (e.g. for Meta/Google cookies) behave like a real ad click.
    const urlWithClickIds = addClickIds(url);

    const pass1 = await capturePass(browser, urlWithClickIds, timeoutMs, notes);
    let pass2: CaptureBundle | null = null;

    if (twoPass && syntheticClickIds) {
      // Second pass keeps the old behavior (forces click ids), but the first pass
      // already includes them. Keeping this for backward-compat + comparison.
      const withIds = addSyntheticClickIds(urlWithClickIds);
      pass2 = await capturePass(browser, withIds, timeoutMs, notes, true);
    }

    const combined = mergeCaptureBundles(pass1, pass2);

    const rootDomain = getRootDomain(url);
    if (!rootDomain) {
      notes.push(
        "Could not determine root domain; treating everything as third-party.",
      );
    }

    // Signals
    const watchedSubdomainRootCookieSets = rootDomain
      ? detectWatchedSubdomainRootCookieSets(
          combined.cookieSetEvents,
          rootDomain,
        )
      : [];

    const watchedReqs = rootDomain
      ? detectWatchedSubdomainRequests(combined.requests, rootDomain)
      : { count: 0, hosts: [] as string[] };

    // Cookies (headers + context jar)
    const headerCookies = parseAndClassifyCookiesFromHeaders(
      combined.setCookieHeaders,
      rootDomain,
    );
    const jarCookies = parseAndClassifyCookiesFromContext(
      combined.contextCookies,
      rootDomain,
    );

    const allCookies = dedupeByKey(
      [...headerCookies, ...jarCookies],
      (c) => `${c.name}|${c.domain}|${c.path ?? "/"}`,
    );

    // ONLY cookies we care about
    const trackingCookies = allCookies.filter((c) => c.isTracking);

    // Cookie platform presence score
    const cookiePlatformsPresent = summarizeCookiePlatforms(trackingCookies);
    const cookieBucketScore = scoreCookiePlatformPresence(
      cookiePlatformsPresent,
    ); // 0..90

    // Watched bucket: presence-only
    const watchedSubdomainPresent = watchedReqs.count >= 1;
    const watchedBucketScore = watchedSubdomainPresent ? 90 : 0; // 0..90

    // Overall (still 70/30), then ensure it cannot exceed 30 if no watched subdomains, and cap <= 90.
    let overall = 0.7 * watchedBucketScore + 0.3 * cookieBucketScore;

    // If there are NO watched subdomains, overall should never exceed 30% by construction.
    // But enforce anyway to prevent future scoring tweaks from breaking this rule.
    if (!watchedSubdomainPresent) {
      overall = Math.min(overall, 27); // 30% of 90 = 27
    }

    const wasOver90 = overall > 90;
    overall = Math.min(overall, 90);

    const overallScore = Math.round(clamp(overall, 0, 90));
    const letterGrade = toLetterGrade(overallScore);

    // Platform presence reports (presence-only, capped at 90)
    const platforms: PlatformReport[] = (
      ["Meta", "Google Analytics", "Google Ads", "TikTok", "LinkedIn"] as const
    ).map((p) => scorePlatformPresenceOnly(p, trackingCookies));

    const recommendedActions = buildRecommendedActions({
      watchedSubdomainPresent,
      watchedSubdomainHosts: watchedReqs.hosts,
      cookiePlatformsPresent,
    });

    return {
      url,
      overallScore,
      letterGrade,
      signals: {
        watchedSubdomainHosts: watchedReqs.hosts,
        watchedSubdomainRootCookieSets,
      },
      recommendedActions,
      platforms,
      cookies: {
        tracking: trackingCookies,
      },
      debug: {
        notes,
        loadMs: combined.loadMs,
        scoring: {
          watchedSubdomainPresent,
          watchedSubdomainHosts: watchedReqs.hosts,
          cookiePlatformsPresent,
          watchedBucketScore,
          cookieBucketScore,
          overallCappedTo90: wasOver90,
        },
      },
    };
  } finally {
    await browser.close();
  }
}

// -----------------------------
// Capture
// -----------------------------
type ContextCookie = {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number;
  httpOnly: boolean;
  secure: boolean;
  sameSite: "Strict" | "Lax" | "None";
};

type CaptureBundle = {
  loadMs: number;
  setCookieHeaders: string[];
  cookieSetEvents: Array<{
    responseUrl: string;
    responseHostname: string;
    status: number;
    setCookie: string;
  }>;
  requests: Array<{
    url: string;
    method: string;
    hostname: string;
    status?: number;
    requestHeaders?: Record<string, string>;
    responseHeaders?: Record<string, string>;
    postData?: string | null;
    resourceType?: string;
  }>;
  contextCookies: ContextCookie[];
};

async function capturePass(
  browser: Browser,
  url: string,
  timeoutMs: number,
  notes: string[],
  isSecondPass = false,
): Promise<CaptureBundle> {
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    userAgent:
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    locale: "en-US",
  });
  const page = await context.newPage();

  await page.addInitScript(() => {
    Object.defineProperty(navigator, "webdriver", { get: () => false });
  });

  const setCookieHeaders: string[] = [];
  const cookieSetEvents: CaptureBundle["cookieSetEvents"] = [];
  const reqs: CaptureBundle["requests"] = [];

  page.on("request", async (r: Request) => {
    const u = safeUrl(r.url());
    if (!u) return;

    let postData: string | null = null;
    try {
      postData = r.postData();
    } catch {
      postData = null;
    }

    reqs.push({
      url: r.url(),
      method: r.method(),
      hostname: u.hostname,
      requestHeaders: lowerKeys(await r.allHeaders().catch(() => ({}) as any)),
      postData,
      resourceType: r.resourceType(),
    });
  });

  page.on("response", async (resp: Response) => {
    const headers = await resp.allHeaders().catch(() => ({}) as any);
    const sc = headers["set-cookie"];

    const respUrl = resp.url();
    const u = safeUrl(respUrl);
    const respHostname = u?.hostname?.toLowerCase() ?? "";

    if (sc) {
      const lines = Array.isArray(sc) ? sc : [sc];
      for (const line of lines) {
        setCookieHeaders.push(line);
        cookieSetEvents.push({
          responseUrl: respUrl,
          responseHostname: respHostname,
          status: resp.status(),
          setCookie: line,
        });
      }
    }

    const r = resp.request();
    const last = [...reqs]
      .reverse()
      .find((x) => x.url === r.url() && x.method === r.method());
    if (last) {
      last.status = resp.status();
      last.responseHeaders = lowerKeys(headers as any);
    }
  });

  const start = Date.now();
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: timeoutMs });
    await page.waitForTimeout(1500);
  } catch (e: any) {
    notes.push(
      `${isSecondPass ? "Pass 2" : "Pass 1"} navigation error: ${String(
        e?.message ?? e,
      )}`,
    );
  }
  const loadMs = Date.now() - start;

  try {
    await page.mouse.wheel(0, 800);
    await page.waitForTimeout(750);
  } catch {
    // ignore
  }

  let contextCookies: ContextCookie[] = [];
  try {
    const raw = await context.cookies();
    contextCookies = raw.map((c) => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      expires: c.expires,
      httpOnly: c.httpOnly,
      secure: c.secure,
      sameSite: c.sameSite,
    }));
  } catch {
    contextCookies = [];
  }

  await page.close().catch(() => {});
  await context.close().catch(() => {});

  if (isSecondPass) notes.push("Ran second pass with synthetic click IDs.");

  return {
    loadMs,
    setCookieHeaders,
    cookieSetEvents,
    requests: reqs,
    contextCookies,
  };
}

function mergeCaptureBundles(
  a: CaptureBundle,
  b: CaptureBundle | null,
): CaptureBundle {
  if (!b) return a;

  return {
    loadMs: Math.max(a.loadMs, b.loadMs),
    setCookieHeaders: dedupe([...a.setCookieHeaders, ...b.setCookieHeaders]),
    cookieSetEvents: dedupeByKey(
      [...a.cookieSetEvents, ...b.cookieSetEvents],
      (e) => `${e.responseUrl}::${e.setCookie}`,
    ),
    requests: dedupeByKey(
      [...a.requests, ...b.requests],
      (r) => `${r.method} ${r.url} ${r.postData ?? ""}`,
    ),
    contextCookies: dedupeByKey(
      [...a.contextCookies, ...b.contextCookies],
      (c) => `${c.name}|${c.domain}|${c.path}`,
    ),
  };
}

// -----------------------------
// Watched subdomain detection
// -----------------------------
function detectWatchedSubdomainRequests(
  requests: CaptureBundle["requests"],
  rootDomain: string,
): { count: number; hosts: string[] } {
  const hosts = new Set<string>();

  for (const r of requests) {
    const u = safeUrl(r.url);
    if (!u) continue;

    const h = u.hostname.toLowerCase();
    const rd = rootDomain.toLowerCase();

    if (h === rd) continue;
    if (!h.endsWith(`.${rd}`)) continue;

    const remainder = h.slice(0, h.length - rd.length - 1);
    const labels = remainder.split(".").filter(Boolean);
    const matched = labels.find((l) => WATCHED_SUBDOMAINS.has(l));
    if (matched) hosts.add(h);
  }

  return { count: hosts.size, hosts: [...hosts].sort() };
}

function detectWatchedSubdomainRootCookieSets(
  cookieSetEvents: CaptureBundle["cookieSetEvents"],
  rootDomain: string,
): SubdomainCookieSetSignal[] {
  const out: SubdomainCookieSetSignal[] = [];

  for (const ev of cookieSetEvents) {
    const parsed = parseSetCookie(ev.setCookie);
    if (!parsed) continue;

    const cookieDomain =
      normalizeCookieDomain(parsed.domain) ?? ev.responseHostname.toLowerCase();

    const labels = getSubdomainLabels(ev.responseHostname, rootDomain);
    if (labels.length === 0) continue;

    const matched = labels.find((l) => WATCHED_SUBDOMAINS.has(l));
    if (!matched) continue;

    out.push({
      responseUrl: ev.responseUrl,
      responseHostname: ev.responseHostname,
      subdomainLabel: matched,
      cookieName: parsed.name,
      cookieDomain,
      path: parsed.path,
      secure: parsed.secure,
      httpOnly: parsed.httpOnly,
      maxAge: parsed.maxAge ?? null,
    });
  }

  return dedupeByKey(
    out,
    (x) =>
      `${x.responseHostname}|${x.cookieName}|${x.cookieDomain}|${x.path ?? "/"}`,
  );
}

function getSubdomainLabels(hostname: string, rootDomain: string): string[] {
  const h = hostname.toLowerCase();
  const rd = rootDomain.toLowerCase();

  if (h === rd) return [];
  if (!h.endsWith(`.${rd}`)) return [];

  const remainder = h.slice(0, h.length - rd.length - 1);
  return remainder.split(".").filter(Boolean);
}

// -----------------------------
// Cookie parsing + classification
// -----------------------------
function parseAndClassifyCookiesFromHeaders(
  setCookieHeaders: string[],
  rootDomain: string | null,
): CookieRecord[] {
  const cookies: CookieRecord[] = [];

  for (const raw of setCookieHeaders) {
    const parsed = parseSetCookie(raw);
    if (!parsed) continue;

    const name = parsed.name;
    const domain = normalizeCookieDomain(parsed.domain) ?? "";
    const hostType = classifyHostType(domain || rootDomain || "", rootDomain);

    const catalogHit = COOKIE_CATALOG.find((e) => e.match(name));
    const inferred = inferProviderFromName(name);

    const provider = (catalogHit?.provider ?? inferred.provider) as Platform;
    const category = (catalogHit?.category ?? inferred.category) as Category;

    const isTracking = Boolean(catalogHit) || isKnownIdentifierCookieName(name);
    const isFirstPartyTracking =
      isTracking && (hostType === "root" || hostType === "firstPartySubdomain");
    const isThirdPartyTracking = isTracking && hostType === "thirdParty";

    cookies.push({
      name,
      domain: domain || "(not-set)",
      path: parsed.path,
      secure: parsed.secure,
      httpOnly: parsed.httpOnly,
      sameSite: parsed.sameSite,
      provider,
      category,
      hostType,
      isTracking,
      isFirstPartyTracking,
      isThirdPartyTracking,
    });
  }

  return dedupeByKey(cookies, (c) => `${c.name}|${c.domain}|${c.path ?? "/"}`);
}

function parseAndClassifyCookiesFromContext(
  contextCookies: ContextCookie[],
  rootDomain: string | null,
): CookieRecord[] {
  const cookies: CookieRecord[] = [];

  for (const c of contextCookies) {
    const name = c.name;
    const domain = normalizeCookieDomain(c.domain) ?? "";
    const hostType = classifyHostType(domain || rootDomain || "", rootDomain);

    const catalogHit = COOKIE_CATALOG.find((e) => e.match(name));
    const inferred = inferProviderFromName(name);

    const provider = (catalogHit?.provider ?? inferred.provider) as Platform;
    const category = (catalogHit?.category ?? inferred.category) as Category;

    const isTracking = Boolean(catalogHit) || isKnownIdentifierCookieName(name);
    const isFirstPartyTracking =
      isTracking && (hostType === "root" || hostType === "firstPartySubdomain");
    const isThirdPartyTracking = isTracking && hostType === "thirdParty";

    cookies.push({
      name,
      domain: domain || "(not-set)",
      path: c.path,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
      provider,
      category,
      hostType,
      isTracking,
      isFirstPartyTracking,
      isThirdPartyTracking,
    });
  }

  return dedupeByKey(cookies, (x) => `${x.name}|${x.domain}|${x.path ?? "/"}`);
}

function parseSetCookie(header: string): {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  maxAge?: number | null;
  expires?: string | null;
} | null {
  const parts = header.split(";").map((p) => p.trim());
  const [nv, ...attrs] = parts;
  if (!nv || !nv.includes("=")) return null;

  const eq = nv.indexOf("=");
  const name = nv.slice(0, eq).trim();
  const value = nv.slice(eq + 1).trim();

  let domain: string | undefined;
  let path: string | undefined;
  let secure = false;
  let httpOnly = false;
  let sameSite: string | undefined;
  let maxAge: number | null = null;
  let expires: string | null = null;

  for (const a of attrs) {
    const [kRaw, ...vRest] = a.split("=");
    const k = (kRaw ?? "").trim().toLowerCase();
    const v = vRest.join("=").trim();

    if (k === "domain") domain = v;
    else if (k === "path") path = v;
    else if (k === "secure") secure = true;
    else if (k === "httponly") httpOnly = true;
    else if (k === "samesite") sameSite = v;
    else if (k === "max-age") {
      const n = Number(v);
      maxAge = Number.isFinite(n) ? n : null;
    } else if (k === "expires") {
      expires = v || null;
    }
  }

  return {
    name,
    value,
    domain,
    path,
    secure,
    httpOnly,
    sameSite,
    maxAge,
    expires,
  };
}

function normalizeCookieDomain(domain?: string): string | null {
  if (!domain) return null;
  const d = domain.trim().toLowerCase();
  if (!d) return null;
  return d.startsWith(".") ? d.slice(1) : d;
}

function classifyHostType(
  cookieDomainOrHost: string,
  rootDomain: string | null,
): HostType {
  const d = cookieDomainOrHost.toLowerCase();
  if (!rootDomain) return "thirdParty";
  if (d === rootDomain) return "root";
  if (d.endsWith(`.${rootDomain}`)) return "firstPartySubdomain";
  return "thirdParty";
}

// -----------------------------
// Platform presence + scoring
// -----------------------------
function summarizeCookiePlatforms(trackingCookies: CookieRecord[]): string[] {
  const present = new Set(
    trackingCookies.map((c) => c.provider).filter((p) => p !== "Unknown"),
  );
  return [...present].sort();
}

// 0..90 (never 100)
function scoreCookiePlatformPresence(platformsPresent: string[]): number {
  const n = platformsPresent.length; // 0..5
  return Math.round((n / 5) * 90);
}

// presence-only, 0..90
function scorePlatformPresenceOnly(
  platform: Exclude<Platform, "Unknown">,
  trackingCookies: CookieRecord[],
): PlatformReport {
  const platformCookies = trackingCookies.filter(
    (c) => c.provider === platform,
  );
  const fpCookies = platformCookies.filter((c) => c.isFirstPartyTracking);
  const tpCookies = platformCookies.filter((c) => c.isThirdPartyTracking);

  const present = platformCookies.length > 0;

  return {
    platform,
    score: present ? 90 : 0,
    present,
    resolveCTA: present
      ? `Cookies for ${platform} are present. Next: verify first-party placement and event routing.`
      : `No ${platform} cookies detected. Add ${platform} cookies (first-party if possible).`,
    debug: {
      cookies: Array.from(new Set(platformCookies.map((c) => c.name))).sort(),
      fpCookies: Array.from(new Set(fpCookies.map((c) => c.name))).sort(),
      tpCookies: Array.from(new Set(tpCookies.map((c) => c.name))).sort(),
    },
  };
}

function buildRecommendedActions(input: {
  watchedSubdomainPresent: boolean;
  watchedSubdomainHosts: string[];
  cookiePlatformsPresent: string[];
}): string {
  const {
    watchedSubdomainPresent,
    watchedSubdomainHosts,
    cookiePlatformsPresent,
  } = input;

  if (!watchedSubdomainPresent) {
    return [
      "No watched first-party tracking subdomain requests were observed.",
      "Add or verify a first-party tracking hostname (e.g. fp/api/collect/track.*) is being requested on key flows.",
    ].join(" ");
  }

  if (cookiePlatformsPresent.length === 0) {
    return [
      "Watched first-party subdomain requests were observed, but no platform cookies were detected.",
      "If you expect Meta/GA/Ads/TikTok/LinkedIn cookies, verify tags fire and cookies are not blocked by consent or browser policies.",
    ].join(" ");
  }

  return `Watched first-party subdomain requests are present (${watchedSubdomainHosts.join(
    ", ",
  )}) and platform cookies were detected (${cookiePlatformsPresent.join(
    ", ",
  )}). Next: validate identifier continuity and event coverage on conversion flows.`;
}

// -----------------------------
// Grade + utilities
// -----------------------------
function toLetterGrade(score: number): Grade {
  if (score >= 81) return "A"; // since 90 is max
  if (score >= 72) return "B";
  if (score >= 63) return "C";
  if (score >= 54) return "D";
  return "F";
}

function getRootDomain(url: string): string | null {
  const u = safeUrl(url);
  if (!u) return null;
  const parsed = parseTld(u.hostname);
  if (!parsed?.domain) return null;
  return parsed.domain.toLowerCase();
}

function addClickIds(url: string): string {
  const u = safeUrl(url);
  if (!u) return url;

  // These values don't need to be valid—just present—so sites behave like
  // a user arrived from a paid click.
  u.searchParams.set("gclid", "1289749812748912");
  u.searchParams.set("fbclid", "092309239058098");
  return u.toString();
}

function addSyntheticClickIds(url: string): string {
  // Keep this name for compatibility, but make it equivalent to addClickIds.
  return addClickIds(url);
}

function safeUrl(s: string): URL | null {
  try {
    return new URL(s);
  } catch {
    return null;
  }
}

function lowerKeys(obj: Record<string, any>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj ?? {})) {
    if (typeof v === "string") out[k.toLowerCase()] = v;
  }
  return out;
}

function clamp(x: number, min: number, max: number): number {
  if (x < min) return min;
  if (x > max) return max;
  return x;
}

function dedupe<T>(arr: T[]): T[] {
  return Array.from(new Set(arr));
}

function dedupeByKey<T>(arr: T[], keyFn: (t: T) => string): T[] {
  const m = new Map<string, T>();
  for (const item of arr) m.set(keyFn(item), item);
  return [...m.values()];
}
