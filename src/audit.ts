// audit.ts
import {
  chromium,
  type Browser,
  type Page,
  type Request,
  type Response,
} from "playwright";
import { parse as parseTld } from "tldts";
import { fileURLToPath } from "node:url";
import path from "node:path";

/**
 * First-party SST audit (transport-gated)
 *
 * Key idea:
 * - Cookies/IDs are NOT proof of server-side tracking.
 * - SST must be "unlocked" by transport evidence:
 *   (a) a first-party collector endpoint receiving analytics-like POSTs, AND
 *   (b) the browser NOT sending direct requests to platform collection endpoints
 *
 * Outputs:
 * - scores: overall, analytics, ads, cookieLifetime, pageSpeed (pageSpeed is intentionally light)
 * - classification: clientSideOnly | fpRelayClient | serverSideLikely | serverSideManaged
 * - debug: why we classified it the way we did
 * - cookies: tables and breakdowns
 * - requests: host breakdown + platform direct evidence
 */

// -----------------------------
// Types
// -----------------------------
type HostGroup = "root" | "subdomain" | "thirdParty";

type Party = "firstParty" | "thirdParty";

type TrackingMethod = "client" | "server" | "unknown";

type CookieRow = {
  name: string;
  value?: string;
  domain: string;
  path?: string;
  party: Party;
  setMethod: "server" | "client" | "unknown";
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: string;
  expires?: string | null;
  lifetimeDays: number | null;
  provider?: string;
  category?: "Advertising" | "Analytics" | "Functional" | "Unknown";
  dataSentTo?: string;
  trackingRelevant: boolean;
};

type RequestRecord = {
  url: string;
  method: string;
  hostname: string;
  group: HostGroup;
  resourceType: string;
  postDataBytes: number;
  hasClickIdKeys: string[];
  looksLikeAnalyticsPayload: boolean;
  status?: number;
  contentType?: string;
};

type HostStats = {
  hostname: string;
  group: HostGroup;
  requests: number;
  posts: number;

  setCookieResponses: number;
  setCookieCount: number;
  cookieNames: Record<string, number>;

  analyticsLikePosts: number;
  clickIdHits: Record<string, number>;
};

type CookieCatalogEntry = {
  provider: string;
  category: "Advertising" | "Analytics" | "Functional" | "Unknown";
  dataSentTo: string;
  defaultLifetimeDays: number | null;
  match: (cookieName: string) => boolean;
};

type AuditResult = {
  url: string;
  debug: any;
  classification:
    | "clientSideOnly"
    | "fpRelayClient"
    | "serverSideLikely"
    | "serverSideManaged";
  scores: {
    overall: number;
    analytics: number;
    ads: number;
    pageSpeed: number;
    cookieLifetime: number;
  };
  cookies: {
    total: number;
    insecure: number;
    serverSet: number;
    firstParty: number;
    thirdParty: number;
    trackingCookies: CookieRow[];
    allCookies: CookieRow[];
  };
  requests: {
    total: number;
    firstParty: number;
    thirdParty: number;
    hosts: HostStats[];
    directPlatformEvidence: {
      ga: boolean;
      meta: boolean;
      googleAds: boolean;
      tiktok: boolean;
      other: string[];
    };
    firstPartyCollectorEvidence: {
      hasCollectorPost: boolean;
      collectorHosts: string[];
      collectorPostCount: number;
      collectorAnalyticsLikePostCount: number;
      collectorClickIdKeys: string[];
    };
  };
};

// -----------------------------
// Catalog (minimal; extend freely)
// -----------------------------
const COOKIE_CATALOG: CookieCatalogEntry[] = [
  // Meta
  {
    provider: "Meta",
    category: "Advertising",
    dataSentTo: "US",
    defaultLifetimeDays: 365,
    match: (n) => n === "_fbp",
  },
  {
    provider: "Meta",
    category: "Advertising",
    dataSentTo: "US",
    defaultLifetimeDays: 90,
    match: (n) => n === "_fbc",
  },
  {
    provider: "Meta",
    category: "Advertising",
    dataSentTo: "US",
    defaultLifetimeDays: 90,
    match: (n) => n === "fr",
  },
  {
    provider: "Meta",
    category: "Advertising",
    dataSentTo: "US",
    defaultLifetimeDays: 730,
    match: (n) => n === "datr",
  },

  // GA / GA4
  {
    provider: "Google Analytics",
    category: "Analytics",
    dataSentTo: "US",
    defaultLifetimeDays: 730,
    match: (n) => n === "_ga",
  },
  {
    provider: "Google Analytics",
    category: "Analytics",
    dataSentTo: "US",
    defaultLifetimeDays: 730,
    match: (n) => n.startsWith("_ga_"),
  },
  {
    provider: "Google Analytics",
    category: "Analytics",
    dataSentTo: "US",
    defaultLifetimeDays: 1,
    match: (n) => n === "_gid",
  },

  // Google Ads
  {
    provider: "Google Ads",
    category: "Advertising",
    dataSentTo: "US",
    defaultLifetimeDays: 90,
    match: (n) => n === "_gcl_au",
  },
  {
    provider: "Google Ads",
    category: "Advertising",
    dataSentTo: "US",
    defaultLifetimeDays: 90,
    match: (n) => n.startsWith("_gcl_"),
  },

  // TikTok
  {
    provider: "TikTok",
    category: "Advertising",
    dataSentTo: "US",
    defaultLifetimeDays: 390,
    match: (n) => n === "_ttp",
  },
];

// -----------------------------
// Platform identifiers (NOT proof of SST)
// Used only as supporting signals once transport is unlocked.
// -----------------------------
const CLICK_ID_KEYS = [
  "gclid",
  "gbraid",
  "wbraid",
  "msclkid",
  "ttclid",
  "fbclid",
];

// -----------------------------
// Known direct platform collection hosts / endpoints (browser -> platform)
// This is the "SST gate": if you see these, you're almost certainly client-side transport.
// -----------------------------
const DIRECT_PLATFORM_HOST_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "ga", re: /(^|\.)google-analytics\.com$/i },
  { name: "ga", re: /(^|\.)analytics\.google\.com$/i },
  { name: "ga", re: /(^|\.)googletagmanager\.com$/i }, // not always direct collect, but strongly client-side tag load
  { name: "ga", re: /(^|\.)g\.doubleclick\.net$/i },
  { name: "googleAds", re: /(^|\.)googleadservices\.com$/i },
  { name: "googleAds", re: /(^|\.)doubleclick\.net$/i },
  { name: "meta", re: /(^|\.)facebook\.com$/i },
  { name: "meta", re: /(^|\.)connect\.facebook\.net$/i },
  { name: "tiktok", re: /(^|\.)tiktok\.com$/i },
  { name: "tiktok", re: /(^|\.)tiktokcdn\.com$/i },
];

// Paths that are strong indicators of direct platform collection (still heuristic)
const DIRECT_PLATFORM_PATH_HINTS: RegExp[] = [
  /\/collect/i,
  /\/g\/collect/i,
  /\/mp\/collect/i,
  /\/tr\/?/i, // facebook.com/tr
  /\/events/i,
  /\/conversion/i,
];

// -----------------------------
// First-party collector path hints (browser -> your domain/subdomain)
// These can be client-relay OR server-side; do not treat as SST without gating.
// -----------------------------
const COLLECTOR_PATH_HINTS: RegExp[] = [
  /\/collect/i,
  /\/collector/i,
  /\/events/i,
  /\/event/i,
  /\/track/i,
  /\/tracking/i,
  /\/analytics/i,
  /\/beacon/i,
  /\/capi/i,
  /\/mp\/collect/i,
  /\/g\/collect/i,
];

// -----------------------------
// Helpers
// -----------------------------
function normalizeHostname(h: string): string {
  return (h || "").toLowerCase().replace(/\.$/, "");
}

function getBaseDomain(hostname: string): string | null {
  const parsed = parseTld(hostname);
  return parsed?.domain ? parsed.domain : null;
}

function groupHost(hostname: string, baseDomain: string): HostGroup {
  const h = normalizeHostname(hostname);
  if (h === baseDomain) return "root";
  if (h.endsWith("." + baseDomain)) return "subdomain";
  return "thirdParty";
}

function ratio(a: number, b: number): number {
  if (!b) return 0;
  return a / b;
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function score100(n: number): number {
  return Math.round(clamp(n, 0, 100));
}

function isDirectPlatformHost(host: string): {
  ga: boolean;
  meta: boolean;
  googleAds: boolean;
  tiktok: boolean;
  other: string[];
} {
  const h = normalizeHostname(host);
  const out = {
    ga: false,
    meta: false,
    googleAds: false,
    tiktok: false,
    other: [] as string[],
  };
  for (const p of DIRECT_PLATFORM_HOST_PATTERNS) {
    if (p.re.test(h)) {
      if (p.name === "ga") out.ga = true;
      else if (p.name === "meta") out.meta = true;
      else if (p.name === "googleAds") out.googleAds = true;
      else if (p.name === "tiktok") out.tiktok = true;
      else out.other.push(p.name);
    }
  }
  return out;
}

function looksAnalyticsLike(
  reqUrl: string,
  method: string,
  postData: string | null,
): boolean {
  const url = reqUrl.toLowerCase();
  const hasPathHint = COLLECTOR_PATH_HINTS.some((re) => re.test(url));
  if (!hasPathHint) return false;

  if (method.toUpperCase() !== "POST") return false;

  // payload heuristics
  const body = (postData || "").toLowerCase();
  if (!body) return false;

  // typical analytics-ish keys
  const bodyHints = [
    "event",
    "client_id",
    "cid",
    "tid",
    "measurement_id",
    "pixel_id",
    "fbp",
    "fbc",
    "user_agent",
    "page_location",
  ];
  const hasBodyHint = bodyHints.some((k) => body.includes(k));
  return hasBodyHint;
}

function findClickIdKeysInText(text: string): string[] {
  const t = (text || "").toLowerCase();
  const hits: string[] = [];
  for (const k of CLICK_ID_KEYS) {
    if (t.includes(k + "=") || t.includes(`"${k}"`) || t.includes(`${k}:`))
      hits.push(k);
  }
  return Array.from(new Set(hits));
}

function catalogMatch(cookieName: string): CookieCatalogEntry | null {
  const n = cookieName || "";
  for (const e of COOKIE_CATALOG) {
    if (e.match(n)) return e;
  }
  return null;
}

function computeLifetimeDays(expires?: string | number | null): number | null {
  if (!expires) return null;
  // Playwright cookies use expires as unix seconds (number). Sometimes string in our normalized row.
  if (typeof expires === "number") {
    if (expires <= 0) return null;
    const ms = expires * 1000 - Date.now();
    return ms > 0 ? Math.round(ms / (1000 * 60 * 60 * 24)) : 0;
  }
  const d = new Date(expires);
  if (Number.isNaN(d.getTime())) return null;
  const ms = d.getTime() - Date.now();
  return ms > 0 ? Math.round(ms / (1000 * 60 * 60 * 24)) : 0;
}

function isInsecureCookie(c: CookieRow): boolean {
  // insecure = not Secure or SameSite=None without Secure (classic bad config)
  if (!c.secure) return true;
  if ((c.sameSite || "").toLowerCase() === "none" && !c.secure) return true;
  return false;
}

// -----------------------------
// Main audit
// -----------------------------
export async function runAudit(
  url: string,
  opts?: { timeoutMs?: number; headless?: boolean },
): Promise<AuditResult> {
  const timeoutMs = opts?.timeoutMs ?? 25_000;
  const headless = opts?.headless ?? true;

  const u = new URL(url.startsWith("http") ? url : `https://${url}`);
  const targetUrl = u.toString();

  const baseDomain = getBaseDomain(u.hostname) || normalizeHostname(u.hostname);

  let browser: Browser | null = null;

  // request / response capture
  const requestRecords: RequestRecord[] = [];
  const hostMap = new Map<string, HostStats>();

  // cookie set-method tracking via Set-Cookie
  const serverSetCookieNames = new Set<string>();
  const responseSetCookieCountByHost = new Map<string, number>();

  // direct platform evidence
  let directPlatform = {
    ga: false,
    meta: false,
    googleAds: false,
    tiktok: false,
    other: [] as string[],
  };

  // collector evidence
  const collectorHosts = new Set<string>();
  let collectorPostCount = 0;
  let collectorAnalyticsLikePostCount = 0;
  const collectorClickIdKeys = new Set<string>();

  // crude perf
  const perf = { navStart: 0, loadMs: 0 };

  try {
    browser = await chromium.launch({ headless });
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      userAgent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    });

    const page = await context.newPage();

    // Hook responses for Set-Cookie headers
    page.on("response", async (res: Response) => {
      const req = res.request();
      const host = normalizeHostname(new URL(req.url()).hostname);
      const headers = await res.headers();
      const setCookie = headers["set-cookie"];
      if (setCookie) {
        // count entries: multiple cookies may be in a single header string
        const count = Array.isArray(setCookie)
          ? setCookie.length
          : setCookie.split(/,(?=[^;]+=[^;]+)/).length;
        responseSetCookieCountByHost.set(
          host,
          (responseSetCookieCountByHost.get(host) || 0) + count,
        );

        // try to parse cookie names
        const raw = Array.isArray(setCookie) ? setCookie : [setCookie];
        for (const line of raw) {
          const parts = line.split(";")[0];
          const eq = parts.indexOf("=");
          if (eq > 0) {
            const name = parts.slice(0, eq).trim();
            if (name) serverSetCookieNames.add(name);
          }
        }

        const hs = hostMap.get(host);
        if (hs) {
          hs.setCookieResponses += 1;
          hs.setCookieCount += count;
        }
      }
    });

    // Hook requests for transport logic
    page.on("request", (req: Request) => {
      const reqUrl = req.url();
      let hostname = "";
      try {
        hostname = normalizeHostname(new URL(reqUrl).hostname);
      } catch {
        hostname = "";
      }
      const group = hostname ? groupHost(hostname, baseDomain) : "thirdParty";
      const method = req.method();
      const resourceType = req.resourceType();
      const postData = req.postData() || "";
      const postDataBytes = postData ? Buffer.byteLength(postData, "utf8") : 0;

      const urlText = reqUrl.toLowerCase();
      const postKeys = findClickIdKeysInText(postData);
      const urlKeys = findClickIdKeysInText(reqUrl);

      const looksLike = looksAnalyticsLike(reqUrl, method, postData);

      // direct platform evidence
      const dp = isDirectPlatformHost(hostname);
      // reinforce only when path hints look like collection
      const pathLooksCollect = DIRECT_PLATFORM_PATH_HINTS.some((re) =>
        re.test(urlText),
      );
      if (dp.ga && pathLooksCollect) directPlatform.ga = true;
      if (dp.meta && pathLooksCollect) directPlatform.meta = true;
      if (dp.googleAds && pathLooksCollect) directPlatform.googleAds = true;
      if (dp.tiktok && pathLooksCollect) directPlatform.tiktok = true;

      // still track “platform present” (scripts) but not as strong as collect
      // NOTE: we purposely do not set directPlatform.ga true just because gtm scripts loaded.

      const rec: RequestRecord = {
        url: reqUrl,
        method,
        hostname,
        group,
        resourceType,
        postDataBytes,
        hasClickIdKeys: Array.from(new Set([...postKeys, ...urlKeys])),
        looksLikeAnalyticsPayload: looksLike,
      };
      requestRecords.push(rec);

      // host stats
      if (hostname) {
        if (!hostMap.has(hostname)) {
          hostMap.set(hostname, {
            hostname,
            group,
            requests: 0,
            posts: 0,
            setCookieResponses: 0,
            setCookieCount: 0,
            cookieNames: {},
            analyticsLikePosts: 0,
            clickIdHits: {},
          });
        }
        const hs = hostMap.get(hostname)!;
        hs.requests += 1;
        if (method === "POST") hs.posts += 1;
        if (looksLike) hs.analyticsLikePosts += 1;
        for (const k of rec.hasClickIdKeys) {
          hs.clickIdHits[k] = (hs.clickIdHits[k] || 0) + 1;
        }
      }

      // collector evidence (first-party only)
      const isFirstPartyHost = group === "root" || group === "subdomain";
      if (
        isFirstPartyHost &&
        method === "POST" &&
        COLLECTOR_PATH_HINTS.some((re) => re.test(urlText))
      ) {
        collectorHosts.add(hostname);
        collectorPostCount += 1;
        if (looksLike) collectorAnalyticsLikePostCount += 1;
        for (const k of rec.hasClickIdKeys) collectorClickIdKeys.add(k);
      }
    });

    perf.navStart = Date.now();
    await page
      .goto(targetUrl, { waitUntil: "load", timeout: timeoutMs })
      .catch(() => null);
    perf.loadMs = Date.now() - perf.navStart;

    // Let late beacons fire
    await page.waitForTimeout(2500).catch(() => null);

    // Pull cookies from context
    const rawCookies = await context.cookies();

    // Convert cookies + party + setMethod
    const allCookies: CookieRow[] = rawCookies.map((c): CookieRow => {
      const party: Party = c.domain.replace(/^\./, "").endsWith(baseDomain)
        ? "firstParty"
        : "thirdParty";

      const setMethod: "server" | "client" | "unknown" =
        serverSetCookieNames.has(c.name) ? "server" : "unknown";

      const lifetimeDays = computeLifetimeDays(c.expires);
      const cat = catalogMatch(c.name);

      return {
        name: c.name,
        value: c.value,
        domain: c.domain,
        path: c.path,
        party,
        setMethod,
        httpOnly: c.httpOnly,
        secure: c.secure,
        sameSite: (c.sameSite as any) || undefined,
        expires: c.expires ? new Date(c.expires * 1000).toISOString() : null,
        lifetimeDays,
        provider: cat?.provider,
        category: cat?.category ?? "Unknown",
        dataSentTo: cat?.dataSentTo,
        trackingRelevant: !!cat,
      };
    });

    const hasCollector =
      collectorPostCount > 0 && collectorAnalyticsLikePostCount > 0;
    const clicky = collectorClickIdKeys.size > 0;

    // Force enhancedCookies to also be CookieRow[] (no unions)
    const enhancedCookies: CookieRow[] = allCookies.map((c): CookieRow => {
      if (c.trackingRelevant) return c;

      const longLived = (c.lifetimeDays ?? 0) >= 30;
      const serverSet = c.setMethod === "server";
      const isFp = c.party === "firstParty";

      if (isFp && serverSet && longLived && hasCollector && clicky) {
        return {
          ...c,
          trackingRelevant: true,
          // keep these inside the CookieRow union values
          category: "Unknown",
          provider: c.provider ?? "Unknown",
        };
      }

      return c;
    });

    // trackingCookies is now safely CookieRow[]
    const trackingCookies: CookieRow[] = enhancedCookies.filter(
      (c) => c.trackingRelevant,
    );

    const fpTrackingCookies = trackingCookies.filter(
      (c) => c.party === "firstParty",
    );
    const tpTrackingCookies = trackingCookies.filter(
      (c) => c.party === "thirdParty",
    );

    const insecureTrackingCookies = trackingCookies.filter(isInsecureCookie);

    // -----------------------------
    // TRANSPORT GATE (SST unlock)
    // -----------------------------
    const hasFirstPartyCollectorPost =
      collectorPostCount > 0 && collectorAnalyticsLikePostCount > 0;

    // direct platform collection: look for any request to platform hosts that also looks like a collect endpoint
    // (we already set directPlatform flags in request hook when host+path looked collect)
    const hasDirectPlatformCollect =
      directPlatform.ga ||
      directPlatform.meta ||
      directPlatform.googleAds ||
      directPlatform.tiktok;

    // SST unlocked only if:
    // - we have first-party collector analytics-like POSTs
    // - and we do NOT have direct platform collection
    const hasServerSideTransport =
      hasFirstPartyCollectorPost && !hasDirectPlatformCollect;

    // Determine "managed" vs "fully first-party" (simple heuristic)
    // If collector hosts include "stape.io" (or similar), call it managed.
    const managedCollector = Array.from(collectorHosts).some((h) =>
      /stape\.io$/i.test(h),
    );

    let classification: AuditResult["classification"] = "clientSideOnly";
    if (hasServerSideTransport)
      classification = managedCollector
        ? "serverSideManaged"
        : "serverSideLikely";
    else if (hasFirstPartyCollectorPost && hasDirectPlatformCollect)
      classification = "fpRelayClient"; // browser posts to FP endpoint but still calls platforms directly

    // -----------------------------
    // Scoring
    // -----------------------------
    // Cookie lifetime score (tracking cookies only)
    const cookieLifetimeScore = (() => {
      if (!trackingCookies.length) return 0;
      const unknownOrShort = trackingCookies.filter(
        (c) => c.lifetimeDays === null || (c.lifetimeDays ?? 0) < 7,
      ).length;
      const insecureRatio = ratio(
        insecureTrackingCookies.length,
        trackingCookies.length,
      );
      const shortRatio = ratio(unknownOrShort, trackingCookies.length);

      // Start at 100, penalize insecure + very short
      let s = 100;
      s -= insecureRatio * 45;
      s -= shortRatio * 35;

      // Slight bonus if most tracking cookies are first-party
      const fpRatio = ratio(fpTrackingCookies.length, trackingCookies.length);
      s += fpRatio * 10;

      return score100(s);
    })();

    // Ads / analytics scores:
    // IMPORTANT: If server-side transport is NOT unlocked, do not award "server-side" credit.
    // These are more like “implementation quality”, but transport dominates.
    const adsScore = (() => {
      // Base from cookie health only (not presence)
      const base = cookieLifetimeScore;

      // If transport unlocked, reward; if direct platform collection, penalize hard
      let s = base;

      if (hasServerSideTransport) {
        s += 12;
        // supporting evidence once unlocked: click IDs present in collector traffic
        if (collectorClickIdKeys.size > 0) s += 8;
      } else {
        // client-side transport: penalize, even if cookies look clean
        s -= 25;
        if (hasDirectPlatformCollect) s -= 15;
      }

      // if no first-party tracking cookies at all, cap
      if (fpTrackingCookies.length === 0) s = Math.min(s, 50);

      return score100(s);
    })();

    const analyticsScore = (() => {
      let s = cookieLifetimeScore;

      if (hasServerSideTransport) {
        s += 10;
      } else {
        s -= 15;
        if (directPlatform.ga) s -= 10;
      }

      if (fpTrackingCookies.length === 0) s = Math.min(s, 50);

      return score100(s);
    })();

    // pageSpeed: intentionally light. Only punish truly bad loads.
    const pageSpeedScore = (() => {
      // 0-2s => 100, 2-6s => linear down to 60, >6s => down to 30
      const ms = perf.loadMs;
      if (ms <= 2000) return 100;
      if (ms <= 6000) {
        const t = (ms - 2000) / 4000;
        return score100(100 - t * 40);
      }
      const t = Math.min(1, (ms - 6000) / 8000);
      return score100(60 - t * 30);
    })();

    // overall: 90% cookie/transport, 10% pageSpeed
    const overallScore = (() => {
      // transport gate affects overall heavily
      // If NOT unlocked, overall can't exceed ~65 even with perfect cookies.
      const core = score100(
        0.45 * adsScore + 0.45 * analyticsScore + 0.1 * cookieLifetimeScore,
      );
      let o = core;

      if (!hasServerSideTransport) {
        // This is the key fix for Bigdill-style false positives
        o = Math.min(o, hasFirstPartyCollectorPost ? 65 : 55);
        if (hasDirectPlatformCollect) o = Math.min(o, 55);
      }

      // blend slight pageSpeed influence
      o = score100(0.9 * o + 0.1 * pageSpeedScore);
      return o;
    })();

    // -----------------------------
    // Assemble result
    // -----------------------------
    const hosts: HostStats[] = Array.from(hostMap.values()).sort(
      (a, b) => b.requests - a.requests,
    );

    const result: AuditResult = {
      url: targetUrl,
      classification,
      debug: {
        baseDomain,
        perf,
        transportGate: {
          hasFirstPartyCollectorPost,
          collectorPostCount,
          collectorAnalyticsLikePostCount,
          hasDirectPlatformCollect,
          hasServerSideTransport,
          managedCollector,
        },
        cookieBreakdown: {
          trackingCookies: trackingCookies.length,
          fpTrackingCookies: fpTrackingCookies.length,
          tpTrackingCookies: tpTrackingCookies.length,
          insecureTrackingCookies: insecureTrackingCookies.length,
        },
      },
      scores: {
        ads: adsScore,
        analytics: analyticsScore,
        pageSpeed: pageSpeedScore,
        cookieLifetime: cookieLifetimeScore,
        overall: overallScore,
      },
      cookies: {
        total: enhancedCookies.length,
        insecure: enhancedCookies.filter(isInsecureCookie).length,
        serverSet: enhancedCookies.filter((c) => c.setMethod === "server")
          .length,
        firstParty: enhancedCookies.filter((c) => c.party === "firstParty")
          .length,
        thirdParty: enhancedCookies.filter((c) => c.party === "thirdParty")
          .length,
        trackingCookies,
        allCookies: enhancedCookies,
      },
      requests: {
        total: requestRecords.length,
        firstParty: requestRecords.filter((r) => r.group !== "thirdParty")
          .length,
        thirdParty: requestRecords.filter((r) => r.group === "thirdParty")
          .length,
        hosts,
        directPlatformEvidence: directPlatform,
        firstPartyCollectorEvidence: {
          hasCollectorPost: hasFirstPartyCollectorPost,
          collectorHosts: Array.from(collectorHosts),
          collectorPostCount,
          collectorAnalyticsLikePostCount,
          collectorClickIdKeys: Array.from(collectorClickIdKeys),
        },
      },
    };

    return result;
  } finally {
    if (browser) await browser.close().catch(() => null);
  }
}

// -----------------------------
// CLI helper (node audit.ts https://example.com)
// -----------------------------
const isMain =
  process.argv[1] &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);

if (isMain) {
  (async () => {
    const url = process.argv[2];
    if (!url) {
      console.error("Usage: ts-node audit.ts <url>");
      process.exit(1);
    }
    const res = await runAudit(url, { headless: true });
    console.log(JSON.stringify(res, null, 2));
  })().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
