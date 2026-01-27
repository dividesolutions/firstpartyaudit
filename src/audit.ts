// src/audit.ts
import {
  chromium,
  type Browser,
  type Request,
  type Response,
} from "playwright";
import { parse as parseTld } from "tldts";

/**
 * First Party Audit — tracking-focused scanner
 *
 * Purpose:
 * - Only "care" about cookies that are associated with tracking (catalog-matched)
 * - Measure first-party vs third-party *tracking* cookies for ad/analytics platforms
 * - Detect first-party routed collectors (server-side / first-party routing signal)
 * - Produce a Stape-like report where client-facing cookie metrics & scores move only
 *   when tracking implementation changes.
 */

// -----------------------------
// Types
// -----------------------------
type HostGroup = "root" | "subdomain" | "thirdParty";

type IdentifierHit = {
  key: string;
  where: "url" | "body" | "cookieName" | "header";
};

type HostStats = {
  hostname: string;
  group: HostGroup;
  requests: number;
  posts: number;

  setCookieResponses: number;
  setCookieCount: number;
  cookieNames: Record<string, number>;

  identifierKeys: Record<string, number>;
  identifierHits: number;

  topPaths: Record<string, number>;
};

type RequestRecord = {
  ts: number;
  url: string;
  method: string;
  hostname: string;
  path: string;
  group: HostGroup;
  resourceType?: string;

  status?: number;
  ok?: boolean;

  postDataBytes?: number;
  setCookieNames?: string[];
  setCookieCount?: number;
  identifierHits?: IdentifierHit[];
};

type CookieParty = "firstParty" | "thirdParty";

type Platform =
  | "Meta"
  | "Google Analytics 4"
  | "Google Ads"
  | "TikTok"
  | "Klaviyo"
  | "Pinterest"
  | "Microsoft Ads"
  | "Other";

type Category = "Advertising" | "Analytics" | "Essential" | "Other";

type TrackingMethod = "Client-side" | "Server-side" | "Client & Server-side";
type TrackerStatus = "All good" | "Improve" | "Not supported";

type ReportCookieRow = {
  name: string;
  provider: Platform;
  category: Category;
  dataSentTo: string; // ex: "US"
  lifetimeDays: number | null; // null if session/unknown
  party: CookieParty;
  setMethod: "server" | "client";
  domain: string;

  // tracking-focused hygiene flags
  secure: boolean;
  sameSite: string | null;
  httpOnly: boolean;
  insecure: boolean; // defined below, only evaluated for tracking cookies
};

type TrackerRow = {
  platform: Platform;
  category: Category;
  dataSentTo: string;
  trackingMethod: TrackingMethod;
  status: TrackerStatus;
  evidence: {
    cookiesMatched: string[];
    requestHostsMatched: string[];
    firstPartyRoutedCollectorPosts: number;
  };
};

type ScoreBlock = {
  overall: number; // 0-100
  analytics: number; // 0-100
  ads: number; // 0-100
  cookieLifetime: number; // 0-100
  pageSpeed: number; // 0-100
};

type PlatformSignal = "Strong" | "Improve" | "Weak" | "Not supported";

type PlatformBreakdownRow = {
  score: number; // 0-100
  signal: PlatformSignal;
  firstParty: boolean;
  serverSide: boolean;
  trackingMethod: TrackingMethod;
  notes?: string;
};

type PlatformsBlock = Record<
  | "googleAds"
  | "meta"
  | "ga4"
  | "klaviyo"
  | "pinterest"
  | "tiktok"
  | "microsoftAds",
  PlatformBreakdownRow
>;

type StapeLikeReport = {
  scores: ScoreBlock;
  platforms: PlatformsBlock;

  /**
   * IMPORTANT:
   * - These counts are tracking-only (catalog matched).
   * - Non-tracking cookies do NOT affect client-facing metrics or scoring.
   */
  cookies: {
    total: number; // total tracking cookies (deduped)
    firstParty: number; // first-party tracking cookies
    thirdParty: number; // third-party tracking cookies
    serverSet: number; // server-set tracking cookies
    insecure: number; // insecure tracking cookies (tracking-only hygiene)
    trackingCookies: ReportCookieRow[]; // curated table rows (tracking-only)
  };

  trackers: {
    detected: TrackerRow[];
    totalDetected: number;
  };

  performance: {
    loadTimeMS: number;
    transferSizeKB: number;
  };

  debug: any; // raw counters, includes non-tracking data
};

// -----------------------------
// Utils
// -----------------------------
function normalizeHostname(hostname: string): string {
  let h = (hostname || "").trim().toLowerCase();
  if (h.startsWith("www.")) h = h.slice(4);
  return h;
}

function getRegistrableDomain(targetUrl: string): string {
  const u = new URL(targetUrl);
  const parsed = parseTld(u.hostname);
  return normalizeHostname(parsed.domain ?? u.hostname);
}

function classifyHost(hostname: string, registrableDomain: string): HostGroup {
  const h = normalizeHostname(hostname);
  const rd = normalizeHostname(registrableDomain);
  if (h === rd) return "root";
  if (h.endsWith("." + rd)) return "subdomain";
  return "thirdParty";
}

function bump(obj: Record<string, number>, key: string, inc = 1) {
  obj[key] = (obj[key] ?? 0) + inc;
}

function getOrInitHostStats(
  hosts: Map<string, HostStats>,
  hostname: string,
  group: HostGroup,
): HostStats {
  const h = normalizeHostname(hostname);
  const existing = hosts.get(h);
  if (existing) return existing;

  const fresh: HostStats = {
    hostname: h,
    group,
    requests: 0,
    posts: 0,
    setCookieResponses: 0,
    setCookieCount: 0,
    cookieNames: {},
    identifierKeys: {},
    identifierHits: 0,
    topPaths: {},
  };
  hosts.set(h, fresh);
  return fresh;
}

function safePath(u: URL): string {
  return u.pathname || "/";
}

function splitSetCookie(raw: string): string[] {
  return raw
    .split(/,(?=[^ ;]+=)/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function extractCookieName(setCookieLine: string): string | null {
  const first = (setCookieLine.split(";")[0] ?? "").trim();
  const eqIdx = first.indexOf("=");
  if (eqIdx <= 0) return null;
  return first.slice(0, eqIdx).trim() || null;
}

function extractCookieDomainFromSetCookie(
  setCookieLine: string,
  fallbackHostname: string,
): string {
  const parts = setCookieLine.split(";").map((p) => p.trim());
  const domainAttr = parts.find((p) => p.toLowerCase().startsWith("domain="));
  const cookieDomain = domainAttr
    ? domainAttr.split("=")[1].trim().replace(/^\./, "")
    : fallbackHostname;
  return normalizeHostname(cookieDomain);
}

function isFirstPartyCookieDomain(cookieDomain: string, baseDomain: string) {
  return normalizeHostname(cookieDomain).endsWith(baseDomain);
}

function clamp(n: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, n));
}

function ratio(n: number, d: number) {
  return d > 0 ? n / d : 0;
}

function uniq<T>(arr: T[]): T[] {
  return [...new Set(arr)];
}

function daysFromCookieExpires(
  expires: number | undefined | null,
): number | null {
  // Playwright cookies: expires is seconds since epoch, or -1 / 0 for session.
  if (!expires || expires <= 0) return null;
  const now = Date.now() / 1000;
  const diff = expires - now;
  if (diff <= 0) return 0;
  return Math.round(diff / (60 * 60 * 24));
}

function isHttpsUrl(url: string): boolean {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}

// -----------------------------
// Identifier keys
// -----------------------------
const IDENTIFIER_KEYS = [
  "gclid",
  "gbraid",
  "wbraid",
  "msclkid",
  "ttclid",
  "fbclid",
  "fbp",
  "fbc",
  "_ga",
  "_gid",
  "cid",
  "client_id",
  "clientid",
  "user_id",
  "userid",
  "anonymous_id",
  "anon_id",
  "external_id",
  "externalid",
  "email_hash",
];

function scanForIdentifiers(opts: {
  url: URL;
  method: string;
  headers: Record<string, string>;
  postData?: string | null;
  cookieNamesFromResponse?: string[];
}): IdentifierHit[] {
  const hits: IdentifierHit[] = [];
  const { url, headers, postData, cookieNamesFromResponse } = opts;

  for (const [k] of url.searchParams.entries()) {
    const key = k.toLowerCase();
    if (IDENTIFIER_KEYS.includes(key)) hits.push({ key, where: "url" });
  }

  for (const [hk, hv] of Object.entries(headers)) {
    const hKey = hk.toLowerCase();
    const hVal = (hv ?? "").toLowerCase();
    for (const idKey of IDENTIFIER_KEYS) {
      if (hKey.includes(idKey)) hits.push({ key: idKey, where: "header" });
      else if (hVal.includes(idKey + "="))
        hits.push({ key: idKey, where: "header" });
    }
  }

  for (const name of cookieNamesFromResponse ?? []) {
    const n = name.toLowerCase();
    if (IDENTIFIER_KEYS.includes(n)) hits.push({ key: n, where: "cookieName" });
    if (n.startsWith("_ga_")) hits.push({ key: "_ga", where: "cookieName" });
  }

  if (postData && postData.length) {
    const lower = postData.toLowerCase();
    for (const idKey of IDENTIFIER_KEYS) {
      if (
        lower.includes(idKey + "=") ||
        lower.includes(`"${idKey}"`) ||
        lower.includes(`'${idKey}'`)
      ) {
        hits.push({ key: idKey, where: "body" });
      }
    }
  }

  const uniqMap = new Map<string, IdentifierHit>();
  for (const h of hits) uniqMap.set(`${h.key}:${h.where}`, h);
  return [...uniqMap.values()];
}

// -----------------------------
// Tracking endpoint hints
// -----------------------------
const COLLECTOR_PATH_HINTS = [
  "/collect",
  "/g/collect",
  "/ccm/collect",
  "/events",
  "/event",
  "/track",
  "/tracking",
  "/pixel",
  "/pixels",
  "/ingest",
  "/beacon",
  "/monorail",
  "/web-pixels",
  "/sdk/",
  "/v1/events",
  "/v2/events",
  "/api/events",
  "/api/collect",
];

function hostLooksLikeTracking(stat: HostStats): boolean {
  if (stat.posts > 0) return true;
  if (stat.setCookieCount > 0) return true;
  if (stat.identifierHits > 0) return true;

  const paths = Object.keys(stat.topPaths || {});
  return paths.some((p) =>
    COLLECTOR_PATH_HINTS.some((hint) => p.toLowerCase().includes(hint)),
  );
}

// -----------------------------
// Cookie Catalog (dictionary) — this is what we "care" about
// -----------------------------
type CookieCatalogEntry = {
  provider: Platform;
  category: Category;
  dataSentTo: string; // "US" default
  match: (cookieName: string) => boolean;
  defaultLifetimeDays?: number;
};

const COOKIE_CATALOG: CookieCatalogEntry[] = [
  // Meta
  {
    provider: "Meta",
    category: "Advertising",
    dataSentTo: "US",
    match: (n) => n === "_fbp",
    defaultLifetimeDays: 365,
  },
  {
    provider: "Meta",
    category: "Advertising",
    dataSentTo: "US",
    match: (n) => n === "_fbc",
    defaultLifetimeDays: 90,
  },

  // GA4 / Google Analytics
  {
    provider: "Google Analytics 4",
    category: "Analytics",
    dataSentTo: "US",
    match: (n) => n === "FPID",
    defaultLifetimeDays: 365,
  },
  {
    provider: "Google Analytics 4",
    category: "Analytics",
    dataSentTo: "US",
    match: (n) => n === "_ga",
    defaultLifetimeDays: 365,
  },
  {
    provider: "Google Analytics 4",
    category: "Analytics",
    dataSentTo: "US",
    match: (n) => /^_ga_.+/.test(n),
    defaultLifetimeDays: 365,
  },

  // Google Ads
  {
    provider: "Google Ads",
    category: "Advertising",
    dataSentTo: "US",
    match: (n) => n === "_gcl_aw",
    defaultLifetimeDays: 7,
  },
  {
    provider: "Google Ads",
    category: "Advertising",
    dataSentTo: "US",
    match: (n) => n === "_gcl_gb",
    defaultLifetimeDays: 7,
  },
  {
    provider: "Google Ads",
    category: "Advertising",
    dataSentTo: "US",
    match: (n) => n === "_gcl_au",
    defaultLifetimeDays: 90,
  },
  {
    provider: "Google Ads",
    category: "Advertising",
    dataSentTo: "US",
    match: (n) => n === "FPGCLAW",
    defaultLifetimeDays: 90,
  },
  {
    provider: "Google Ads",
    category: "Advertising",
    dataSentTo: "US",
    match: (n) => n === "FPGCLGB",
    defaultLifetimeDays: 90,
  },
  {
    provider: "Google Ads",
    category: "Advertising",
    dataSentTo: "US",
    match: (n) => n === "FPAU",
    defaultLifetimeDays: 365,
  },

  // Klaviyo
  {
    provider: "Klaviyo",
    category: "Advertising",
    dataSentTo: "US",
    match: (n) => n === "__kla_id",
    defaultLifetimeDays: 400,
  },

  // Pinterest
  {
    provider: "Pinterest",
    category: "Advertising",
    dataSentTo: "US",
    match: (n) => n === "_epik",
    defaultLifetimeDays: 365,
  },

  // TikTok
  {
    provider: "TikTok",
    category: "Advertising",
    dataSentTo: "US",
    match: (n) => n === "_ttp",
    defaultLifetimeDays: 400,
  },
  {
    provider: "TikTok",
    category: "Advertising",
    dataSentTo: "US",
    match: (n) => n.startsWith("tt_"),
    defaultLifetimeDays: 30,
  },

  // Microsoft Ads
  {
    provider: "Microsoft Ads",
    category: "Advertising",
    dataSentTo: "US",
    match: (n) => n === "_uetsid",
    defaultLifetimeDays: 30,
  },
  {
    provider: "Microsoft Ads",
    category: "Advertising",
    dataSentTo: "US",
    match: (n) => n === "_uetvid",
    defaultLifetimeDays: 390,
  },
];

// -----------------------------
// Tracker catalog (request-domain evidence)
// -----------------------------
type TrackerCatalogEntry = {
  platform: Platform;
  category: Category;
  dataSentTo: string;
  requestHostPatterns: RegExp[];
  supportsServerSide: boolean;
  cookieMatchProviders: Platform[];
};

const TRACKER_CATALOG: TrackerCatalogEntry[] = [
  {
    platform: "Meta",
    category: "Advertising",
    dataSentTo: "US",
    requestHostPatterns: [
      /facebook\.com/i,
      /fbcdn\.net/i,
      /connect\.facebook\.net/i,
      /graph\.facebook\.com/i,
    ],
    supportsServerSide: true,
    cookieMatchProviders: ["Meta"],
  },
  {
    platform: "Google Analytics 4",
    category: "Analytics",
    dataSentTo: "US",
    requestHostPatterns: [
      /google-analytics\.com/i,
      /analytics\.google\.com/i,
      /googletagmanager\.com/i,
    ],
    supportsServerSide: true,
    cookieMatchProviders: ["Google Analytics 4"],
  },
  {
    platform: "Google Ads",
    category: "Advertising",
    dataSentTo: "US",
    requestHostPatterns: [
      /doubleclick\.net/i,
      /googleadservices\.com/i,
      /googlesyndication\.com/i,
    ],
    supportsServerSide: true,
    cookieMatchProviders: ["Google Ads"],
  },
  {
    platform: "Klaviyo",
    category: "Advertising",
    dataSentTo: "US",
    requestHostPatterns: [/klaviyo\.com/i, /klaviyomail\.com/i],
    supportsServerSide: true,
    cookieMatchProviders: ["Klaviyo"],
  },
  {
    platform: "Pinterest",
    category: "Advertising",
    dataSentTo: "US",
    requestHostPatterns: [/pinterest\.com/i, /ct\.pinterest\.com/i],
    supportsServerSide: true,
    cookieMatchProviders: ["Pinterest"],
  },
  {
    platform: "TikTok",
    category: "Advertising",
    dataSentTo: "US",
    requestHostPatterns: [
      /tiktok\.com/i,
      /ads\.tiktok\.com/i,
      /business\.tiktok\.com/i,
    ],
    supportsServerSide: true,
    cookieMatchProviders: ["TikTok"],
  },
  {
    platform: "Microsoft Ads",
    category: "Advertising",
    dataSentTo: "US",
    requestHostPatterns: [/bing\.com/i, /bat\.bing\.com/i],
    supportsServerSide: false,
    cookieMatchProviders: ["Microsoft Ads"],
  },
];

// -----------------------------
// Main
// -----------------------------
const RUN_ATTRIBUTION_SIMULATION = true;

function withSyntheticClickIds(urlStr: string) {
  const u = new URL(urlStr);
  if (!u.searchParams.has("gclid")) u.searchParams.set("gclid", "TEST_GCLID");
  if (!u.searchParams.has("gbraid"))
    u.searchParams.set("gbraid", "TEST_GBRAID");
  if (!u.searchParams.has("wbraid"))
    u.searchParams.set("wbraid", "TEST_WBRAID");
  if (!u.searchParams.has("fbclid"))
    u.searchParams.set("fbclid", "TEST_FBCLID");
  if (!u.searchParams.has("msclkid"))
    u.searchParams.set("msclkid", "TEST_MSCLKID");
  if (!u.searchParams.has("ttclid"))
    u.searchParams.set("ttclid", "TEST_TTCLID");
  return u.toString();
}

function catalogMatch(cookieName: string): CookieCatalogEntry | null {
  const n = String(cookieName || "").trim();
  for (const entry of COOKIE_CATALOG) {
    if (entry.match(n)) return entry;
  }
  return null;
}

/**
 * Tracking-focused insecurity:
 * - If site is HTTPS and cookie is not Secure => insecure
 * - If SameSite=None and cookie is not Secure => insecure
 *
 * (We only compute this for tracking cookies.)
 */
function isTrackingCookieInsecure(opts: {
  isHttps: boolean;
  secure: boolean;
  sameSite: string | null;
}): boolean {
  const { isHttps, secure, sameSite } = opts;
  if (isHttps && !secure) return true;
  if ((sameSite ?? "") === "None" && !secure) return true;
  return false;
}

export async function runAudit(targetUrl: string): Promise<StapeLikeReport> {
  const browser: Browser = await chromium.launch({
    headless: true,
    args: ["--no-sandbox"],
  });

  try {
    const context = await browser.newContext();
    const page = await context.newPage();

    const baseDomain = getRegistrableDomain(targetUrl);
    const isHttps = isHttpsUrl(targetUrl);

    const requestRecords: RequestRecord[] = [];
    const hosts = new Map<string, HostStats>();
    const reqToIndex = new Map<Request, number>();

    const allServerCookies: Array<{
      cookie: string; // "name=value"
      domain: string;
      setBy: string;
      source: "server-set";
    }> = [];

    const browserCookies: any[] = [];

    // ---- Request listener
    page.on("request", (req) => {
      try {
        const url = new URL(req.url());
        const hostname = normalizeHostname(url.hostname);
        const group = classifyHost(hostname, baseDomain);

        const method = req.method();
        const headers = req.headers();
        const postData = req.postData() ?? null;
        const postDataBytes = postData
          ? Buffer.byteLength(postData, "utf8")
          : 0;

        const record: RequestRecord = {
          ts: Date.now(),
          url: req.url(),
          method,
          hostname,
          path: safePath(url),
          group,
          resourceType: req.resourceType(),
          postDataBytes,
          identifierHits: scanForIdentifiers({
            url,
            method,
            headers,
            postData,
          }),
        };

        const idx = requestRecords.push(record) - 1;
        reqToIndex.set(req, idx);

        const stat = getOrInitHostStats(hosts, hostname, group);
        stat.requests += 1;
        if (method === "POST") stat.posts += 1;
        bump(stat.topPaths, record.path);

        for (const hit of record.identifierHits ?? []) {
          stat.identifierHits += 1;
          bump(stat.identifierKeys, hit.key);
        }
      } catch {
        /* ignore */
      }
    });

    // ---- Response listener (Set-Cookie correlation)
    page.on("response", async (resp: Response) => {
      try {
        const url = new URL(resp.url());
        const hostname = normalizeHostname(url.hostname);
        const group = classifyHost(hostname, baseDomain);

        const headers = await resp.allHeaders();
        const req = resp.request();

        const idx = reqToIndex.get(req);
        const record = idx !== undefined ? requestRecords[idx] : undefined;
        if (record) {
          record.status = resp.status();
          record.ok = resp.ok();
        }

        const setCookieHeader =
          (headers as any)["set-cookie"] ?? (headers as any)["Set-Cookie"];

        if (!setCookieHeader) return;

        const rawCookieLines = Array.isArray(setCookieHeader)
          ? setCookieHeader.flatMap((v: string) => splitSetCookie(v))
          : splitSetCookie(setCookieHeader);

        const cookieNamesForThisResponse: string[] = [];

        rawCookieLines.forEach((line) => {
          const name = extractCookieName(line);
          if (name) cookieNamesForThisResponse.push(name);

          const cookieDomain = extractCookieDomainFromSetCookie(line, hostname);

          allServerCookies.push({
            cookie: (line.split(";")[0] ?? "").trim(),
            domain: cookieDomain,
            setBy: hostname,
            source: "server-set",
          });
        });

        const stat = getOrInitHostStats(hosts, hostname, group);
        stat.setCookieResponses += 1;
        stat.setCookieCount += cookieNamesForThisResponse.length;
        for (const n of cookieNamesForThisResponse) bump(stat.cookieNames, n);

        if (!record) return;

        record.setCookieNames = cookieNamesForThisResponse;
        record.setCookieCount = cookieNamesForThisResponse.length;

        const extraHits = scanForIdentifiers({
          url: new URL(record.url),
          method: record.method,
          headers: req.headers(),
          postData: req.postData(),
          cookieNamesFromResponse: cookieNamesForThisResponse,
        });

        const merged = new Map<string, IdentifierHit>();
        for (const h of record.identifierHits ?? [])
          merged.set(`${h.key}:${h.where}`, h);
        for (const h of extraHits) merged.set(`${h.key}:${h.where}`, h);
        record.identifierHits = [...merged.values()];

        // rebuild per-host identifier counts
        stat.identifierHits = 0;
        stat.identifierKeys = {};
        for (const r of requestRecords) {
          if (normalizeHostname(r.hostname) !== stat.hostname) continue;
          for (const hit of r.identifierHits ?? []) {
            stat.identifierHits += 1;
            bump(stat.identifierKeys, hit.key);
          }
        }
      } catch {
        /* ignore */
      }
    });

    // ---- Navigation pass #1
    const start = Date.now();
    try {
      await page.goto(targetUrl, {
        waitUntil: "domcontentloaded",
        timeout: 45000,
      });
      await page
        .waitForLoadState("networkidle", { timeout: 15000 })
        .catch(() => {
          /* ignore */
        });
    } catch {
      /* ignore */
    }
    const loadTimeMS = Date.now() - start;

    // ---- small interaction
    try {
      await page.waitForTimeout(1500);
      await page.mouse.wheel(0, 1200);
      await page.waitForTimeout(1500);
    } catch {
      /* ignore */
    }

    // ---- Optional navigation pass #2 (synthetic click IDs)
    if (RUN_ATTRIBUTION_SIMULATION) {
      try {
        const testUrl = withSyntheticClickIds(targetUrl);
        await page.goto(testUrl, {
          waitUntil: "domcontentloaded",
          timeout: 45000,
        });
        await page
          .waitForLoadState("networkidle", { timeout: 15000 })
          .catch(() => {
            /* ignore */
          });
        await page.waitForTimeout(1500);
      } catch {
        /* ignore */
      }
    }

    // ---- collect cookies (raw input)
    const cookies = await context.cookies();
    cookies.forEach((c) => browserCookies.push(c));

    // Correlate browser cookies to server-set cookies
    browserCookies.forEach((c) => {
      const match = allServerCookies.find((s) => {
        const serverName = s.cookie.split("=")[0];
        if (c.name !== serverName) return false;

        const cd = normalizeHostname(String(c.domain ?? "")).replace(/^\./, "");
        const sd = normalizeHostname(String(s.domain ?? "")).replace(/^\./, "");
        return cd === sd || cd.endsWith("." + sd) || sd.endsWith("." + cd);
      });

      if (match) {
        c.setByServer = match.setBy;
        c.setCookieDomain = match.domain;
      }
    });

    // ---- endpoints grouping
    const endpoints = {
      root: {} as Record<string, HostStats>,
      subdomains: {} as Record<string, HostStats>,
      thirdParty: {} as Record<string, HostStats>,
    };

    for (const stat of hosts.values()) {
      if (stat.group === "root") endpoints.root[stat.hostname] = stat;
      else if (stat.group === "subdomain")
        endpoints.subdomains[stat.hostname] = stat;
      else endpoints.thirdParty[stat.hostname] = stat;
    }

    // behavior-based first-party routed collector hosts
    const trackingFirstPartySubdomains = Object.values(
      endpoints.subdomains,
    ).filter(hostLooksLikeTracking);
    const trackingRoot = Object.values(endpoints.root).filter(
      hostLooksLikeTracking,
    );

    const trackingHosts = new Set<string>([
      ...trackingFirstPartySubdomains.map((h) => normalizeHostname(h.hostname)),
      ...trackingRoot.map((h) => normalizeHostname(h.hostname)),
    ]);

    const trackingFirstPartySubdomainHosts = new Set<string>(
      trackingFirstPartySubdomains.map((h) => normalizeHostname(h.hostname)),
    );

    // ---- First-party collector POSTs
    const firstPartyCollectorPOSTs = requestRecords.filter((r) => {
      if (r.group === "thirdParty") return false;
      if (r.method !== "POST") return false;
      return trackingHosts.has(normalizeHostname(r.hostname));
    });

    // Identifier keys on first-party collector posts
    const fpCollectorIdKeys = new Set<string>();
    for (const r of firstPartyCollectorPOSTs) {
      for (const hit of r.identifierHits ?? []) fpCollectorIdKeys.add(hit.key);
    }

    const PLATFORM_ID_KEYS: Record<Platform, string[]> = {
      Meta: ["fbclid", "fbp", "fbc"],
      "Google Analytics 4": ["_ga", "cid", "client_id", "clientid"],
      "Google Ads": ["gclid", "gbraid", "wbraid"],
      TikTok: ["ttclid"],
      Klaviyo: ["external_id", "email_hash"],
      Pinterest: ["epik", "external_id"],
      "Microsoft Ads": ["msclkid"],
      Other: [],
    };

    function platformHasServerSignal(p: Platform) {
      const keys = PLATFORM_ID_KEYS[p] ?? [];
      if (!keys.length) return false;
      for (const k of keys) {
        if (fpCollectorIdKeys.has(k)) return true;
      }
      return false;
    }

    // -----------------------------
    // TRACKING-ONLY cookies (catalog matched)
    // -----------------------------
    const trackingCookieRowsRaw: ReportCookieRow[] = [];

    for (const c of browserCookies) {
      const entry = catalogMatch(c.name);
      if (!entry) continue;

      const party: CookieParty = isFirstPartyCookieDomain(c.domain, baseDomain)
        ? "firstParty"
        : "thirdParty";

      const setMethod: "server" | "client" = c.setByServer
        ? "server"
        : "client";

      const lifetime = daysFromCookieExpires(c.expires);
      const lifetimeDays = lifetime ?? entry.defaultLifetimeDays ?? null;

      const secure = Boolean(c.secure);
      const sameSite =
        c.sameSite === undefined || c.sameSite === null
          ? null
          : String(c.sameSite);
      const httpOnly = Boolean(c.httpOnly);

      const insecure = isTrackingCookieInsecure({
        isHttps,
        secure,
        sameSite,
      });

      trackingCookieRowsRaw.push({
        name: c.name,
        provider: entry.provider,
        category: entry.category,
        dataSentTo: entry.dataSentTo,
        lifetimeDays,
        party,
        setMethod,
        domain: String(c.domain ?? ""),
        secure,
        sameSite,
        httpOnly,
        insecure,
      });
    }

    // Dedup tracking rows by cookie name (stable metrics for clients)
    const seen = new Set<string>();
    const trackingCookies = trackingCookieRowsRaw.filter((r) => {
      if (seen.has(r.name)) return false;
      seen.add(r.name);
      return true;
    });

    const fpTrackingCookies = trackingCookies.filter(
      (c) => c.party === "firstParty",
    );
    const tpTrackingCookies = trackingCookies.filter(
      (c) => c.party === "thirdParty",
    );

    const serverSetTrackingCookies = trackingCookies.filter(
      (c) => c.setMethod === "server",
    );

    const insecureTrackingCookies = trackingCookies.filter((c) => c.insecure);

    // -----------------------------
    // Tracker detection (cookie + request evidence)
    // -----------------------------
    const thirdPartyRequestHostnames = requestRecords
      .filter((r) => r.group === "thirdParty")
      .map((r) => normalizeHostname(r.hostname));

    // cookie evidence grouped by platform (tracking-only)
    const cookiesByProvider: Record<string, string[]> = {};
    for (const row of trackingCookies) {
      cookiesByProvider[row.provider] = cookiesByProvider[row.provider] ?? [];
      cookiesByProvider[row.provider].push(row.name);
    }

    function hostsMatching(patterns: RegExp[]): string[] {
      return uniq(
        thirdPartyRequestHostnames.filter((h) =>
          patterns.some((re) => re.test(h)),
        ),
      );
    }

    const trackersDetected: TrackerRow[] = [];
    for (const t of TRACKER_CATALOG) {
      const cookieEvidence = uniq(
        (cookiesByProvider[t.platform] ?? []).filter(Boolean),
      );
      const requestEvidence = hostsMatching(t.requestHostPatterns);

      const detected = cookieEvidence.length > 0 || requestEvidence.length > 0;
      if (!detected) continue;

      const hasClient = requestEvidence.length > 0 || cookieEvidence.length > 0;
      const hasServer =
        firstPartyCollectorPOSTs.length > 0 &&
        platformHasServerSignal(t.platform);

      let trackingMethod: TrackingMethod = "Client-side";
      if (hasServer && hasClient) trackingMethod = "Client & Server-side";
      else if (hasServer) trackingMethod = "Server-side";

      let status: TrackerStatus = "All good";

      if (!t.supportsServerSide) {
        status = "Not supported";
      } else {
        const isAds = t.category === "Advertising";
        if (isAds && trackingMethod === "Client-side") status = "Improve";
        if (t.platform === "Klaviyo" && trackingMethod === "Client-side")
          status = "Improve";
      }

      trackersDetected.push({
        platform: t.platform,
        category: t.category,
        dataSentTo: t.dataSentTo,
        trackingMethod,
        status,
        evidence: {
          cookiesMatched: cookieEvidence,
          requestHostsMatched: requestEvidence,
          firstPartyRoutedCollectorPosts: firstPartyCollectorPOSTs.length,
        },
      });
    }

    // -----------------------------
    // Scoring (tracking-only)
    // -----------------------------
    const pageSpeed = (() => {
      const ms = loadTimeMS;
      if (ms <= 2000) return 95;
      if (ms <= 4000) return 85;
      if (ms <= 7000) return 75;
      if (ms <= 12000) return 65;
      if (ms <= 20000) return 55;
      return 45;
    })();

    const cookieLifetime = (() => {
      if (!trackingCookies.length) return 35;

      let score = 70;

      const longLived = trackingCookies.filter(
        (c) => (c.lifetimeDays ?? 0) >= 90,
      ).length;
      score += Math.min(20, longLived * 5);

      const shortLived = trackingCookies.filter(
        (c) => c.lifetimeDays === null || (c.lifetimeDays ?? 0) < 7,
      ).length;
      score -= Math.min(25, shortLived * 6);

      return clamp(score, 0, 100);
    })();

    /**
     * Cookie score:
     * - Dominated by first-party share of tracking cookies
     * - Only penalizes insecurity for tracking cookies
     * - Only penalizes short/unknown lifetime for tracking cookies
     */
    const cookieScore = (() => {
      if (!trackingCookies.length) return 0;

      const fpRatio = ratio(fpTrackingCookies.length, trackingCookies.length);
      const tpRatio = ratio(tpTrackingCookies.length, trackingCookies.length);

      const insecureRatio = ratio(
        insecureTrackingCookies.length,
        trackingCookies.length,
      );

      const shortOrUnknown = trackingCookies.filter(
        (c) => c.lifetimeDays === null || (c.lifetimeDays ?? 0) < 7,
      ).length;
      const shortRatio = ratio(shortOrUnknown, trackingCookies.length);

      let score = 0;

      // main driver: first-party tracking coverage
      score += fpRatio * 75;

      // third-party dependency hurts
      score -= tpRatio * 35;

      // tracking cookie hygiene (small)
      score -= clamp(insecureRatio * 10, 0, 10);

      // short/unknown lifetimes among tracking cookies
      score -= clamp(shortRatio * 15, 0, 15);

      // small bonus for multiple FP tracking cookies (saturates fast)
      score += Math.min(10, fpTrackingCookies.length * 2);

      return clamp(Math.round(score), 0, 100);
    })();

    function makePlatformRow(p: Platform): PlatformBreakdownRow {
      const tracker = trackersDetected.find((t) => t.platform === p);

      const cookieRows = trackingCookies.filter((c) => c.provider === p);
      const hasCookies = cookieRows.length > 0;
      const hasFirstPartyCookies = cookieRows.some(
        (c) => c.party === "firstParty",
      );

      const hasServer =
        firstPartyCollectorPOSTs.length > 0 && platformHasServerSignal(p);

      const trackingMethod: TrackingMethod =
        tracker?.trackingMethod ??
        (hasServer && hasCookies
          ? "Client & Server-side"
          : hasServer
            ? "Server-side"
            : hasCookies
              ? "Client-side"
              : "Client-side");

      const supportsServerSide =
        TRACKER_CATALOG.find((t) => t.platform === p)?.supportsServerSide ??
        true;

      let score = 25;
      if (hasCookies) score = 60;
      if (hasFirstPartyCookies) score += 15; // slightly more emphasis (your product)
      if (hasServer) score += 20;

      const isAdsPlatform = p !== "Google Analytics 4" && p !== "Other";
      if (isAdsPlatform && !hasServer && supportsServerSide) score -= 10;

      if (!supportsServerSide) score = Math.min(score, 70);

      score = clamp(score, 0, 100);

      let signal: PlatformSignal = "Improve";
      if (!supportsServerSide) signal = "Not supported";
      else if (score >= 80 && (hasServer || hasFirstPartyCookies))
        signal = "Strong";
      else if (score < 60) signal = "Weak";

      const notes = !supportsServerSide
        ? "Limited server-side support"
        : isAdsPlatform && !hasServer
          ? "Client-side only (routing recommended)"
          : hasServer
            ? "Server-side signal detected"
            : hasFirstPartyCookies
              ? "First-party tracking cookie present"
              : undefined;

      return {
        score: Math.round(score),
        signal,
        firstParty: hasFirstPartyCookies,
        serverSide: hasServer,
        trackingMethod,
        notes,
      };
    }

    const platforms: PlatformsBlock = {
      googleAds: makePlatformRow("Google Ads"),
      meta: makePlatformRow("Meta"),
      ga4: makePlatformRow("Google Analytics 4"),
      klaviyo: makePlatformRow("Klaviyo"),
      pinterest: makePlatformRow("Pinterest"),
      tiktok: makePlatformRow("TikTok"),
      microsoftAds: makePlatformRow("Microsoft Ads"),
    };

    const analytics = (() => {
      const gaCookies = trackingCookies.filter(
        (c) => c.provider === "Google Analytics 4",
      );
      const hasAnyGA = gaCookies.length > 0;
      const hasGAFirstParty = gaCookies.some((c) => c.party === "firstParty");

      let score = 0;
      if (hasAnyGA) score += 50;
      if (hasGAFirstParty) score += 30;
      if (platforms.ga4.serverSide) score += 20;

      return clamp(Math.round(score), 0, 100);
    })();

    const ads = (() => {
      const google = platforms.googleAds.score;
      const meta = platforms.meta.score;
      const microsoft = platforms.microsoftAds.score;

      const othersAvg =
        (platforms.klaviyo.score +
          platforms.pinterest.score +
          platforms.tiktok.score) /
        3;

      const score =
        google * 0.4 + meta * 0.3 + microsoft * 0.15 + othersAvg * 0.15;

      return clamp(Math.round(score), 0, 100);
    })();

    // Overall: tracking-cookie dominated
    let overall = clamp(
      Math.round(cookieScore * 0.92 + pageSpeed * 0.08),
      0,
      100,
    );

    // Hard rule: if there are NO first-party tracking cookies (catalog-matched),
    // the site cannot score above 50.
    if (fpTrackingCookies.length === 0) {
      overall = Math.min(overall, 50);
    }

    const report: StapeLikeReport = {
      scores: {
        overall,
        analytics: Math.round(analytics),
        ads: Math.round(ads),
        cookieLifetime: Math.round(cookieLifetime),
        pageSpeed: Math.round(pageSpeed),
      },
      platforms,
      cookies: {
        total: trackingCookies.length,
        firstParty: fpTrackingCookies.length,
        thirdParty: tpTrackingCookies.length,
        serverSet: serverSetTrackingCookies.length,
        insecure: insecureTrackingCookies.length,
        trackingCookies: trackingCookies.sort((a, b) =>
          a.provider > b.provider ? 1 : -1,
        ),
      },
      trackers: {
        detected: trackersDetected.sort((a, b) =>
          a.platform > b.platform ? 1 : -1,
        ),
        totalDetected: trackersDetected.length,
      },
      performance: {
        loadTimeMS,
        transferSizeKB: Math.round((await page.content()).length / 1024),
      },
      debug: {
        baseDomain,
        isHttps,

        // scoring internals (tracking-only)
        cookieScore,
        fpTrackingCookieCount: fpTrackingCookies.length,
        tpTrackingCookieCount: tpTrackingCookies.length,
        insecureTrackingCookieCount: insecureTrackingCookies.length,

        // routing / server-side evidence
        trackingHosts: Array.from(trackingHosts),
        trackingFirstPartySubdomainHosts: Array.from(
          trackingFirstPartySubdomainHosts,
        ),
        firstPartyCollectorPOSTs: firstPartyCollectorPOSTs.length,
        fpCollectorIdKeys: Array.from(fpCollectorIdKeys),

        // raw request counts
        requestCounts: {
          total: requestRecords.length,
          thirdParty: requestRecords.filter((r) => r.group === "thirdParty")
            .length,
          firstParty: requestRecords.filter((r) => r.group !== "thirdParty")
            .length,
        },

        // raw cookie info (non-tracking) lives ONLY in debug now
        allCookies: {
          total: browserCookies.length,
          firstParty: browserCookies.filter((c) =>
            normalizeHostname(c.domain).endsWith(baseDomain),
          ).length,
          thirdParty: browserCookies.filter(
            (c) => !normalizeHostname(c.domain).endsWith(baseDomain),
          ).length,
          serverSet: browserCookies.filter((c) => Boolean(c.setByServer))
            .length,
        },
      },
    };

    return report;
  } finally {
    await browser.close().catch(() => {
      /* ignore */
    });
  }
}
