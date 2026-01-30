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

/**
 * Known tracking subdomain prefixes
 * Cookies set by these subdomains are considered first-party tracking cookies
 */
const TRACKING_SUBDOMAIN_PREFIXES = [
  "api",
  "app",
  "edge",
  "ingest",
  "log",
  "logs",
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
];

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

/**
 * Check if a hostname is a tracking subdomain
 * Returns true only if the hostname matches one of the known tracking subdomain patterns
 */
function isTrackingSubdomain(hostname: string, baseDomain: string): boolean {
  const h = normalizeHostname(hostname);
  const bd = normalizeHostname(baseDomain);

  // Must be a subdomain of the base domain
  if (!h.endsWith("." + bd)) {
    return false;
  }

  // Extract the subdomain prefix (everything before the base domain)
  const subdomain = h.slice(0, -(bd.length + 1)); // +1 for the dot

  // Check if the subdomain matches any tracking prefix
  // Handle multi-level subdomains by checking the leftmost part
  const parts = subdomain.split(".");
  const leftmost = parts[0];

  return TRACKING_SUBDOMAIN_PREFIXES.includes(leftmost);
}

/**
 * Determine if a cookie domain is a first-party tracking domain
 * A cookie is first-party tracking ONLY if it was set by a tracking subdomain
 */
function isFirstPartyTrackingCookie(
  cookieDomain: string,
  baseDomain: string,
  trackingSubdomains: Set<string>,
): boolean {
  const cd = normalizeHostname(cookieDomain);
  const bd = normalizeHostname(baseDomain);

  // Cookie domain must be within the base domain
  if (!cd.endsWith(bd)) {
    return false;
  }

  // Check if this cookie domain matches any of the detected tracking subdomains
  // or is set by one of them (cookies can be set with domain=.example.com)
  for (const trackingSub of trackingSubdomains) {
    const ts = normalizeHostname(trackingSub);
    // Cookie is first-party tracking if:
    // 1. Cookie domain exactly matches a tracking subdomain
    // 2. Cookie domain is set to cover a tracking subdomain (e.g., .data.example.com or .example.com when set by data.example.com)
    if (cd === ts || ts.endsWith("." + cd) || cd === bd) {
      // For the base domain case, we need to check if it was actually set by a tracking subdomain
      // This will be validated by checking against trackingSubdomains
      if (cd === bd) {
        // Only consider it first-party tracking if there's evidence of tracking subdomains
        return trackingSubdomains.size > 0;
      }
      return true;
    }
  }

  return false;
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
  return diff > 0 ? Math.round(diff / 86400) : null;
}

// -----------------------------
// Tracker Catalog (subset)
// -----------------------------
const TRACKER_CATALOG = [
  {
    platform: "Meta" as Platform,
    category: "Advertising" as Category,
    dataSentTo: "US",
    cookieNames: ["_fbp", "_fbc", "fr"],
    hostPatterns: [
      "facebook.com",
      "connect.facebook.net",
      "facebook.net",
      "fbcdn.net",
    ],
    identifierKeys: ["fbp", "fbc", "fbclid"],
    supportsServerSide: true,
  },
  {
    platform: "Google Analytics 4" as Platform,
    category: "Analytics" as Category,
    dataSentTo: "US",
    cookieNames: ["_ga", "_ga_"],
    hostPatterns: [
      "google-analytics.com",
      "googletagmanager.com",
      "analytics.google.com",
    ],
    identifierKeys: ["_ga", "cid", "client_id"],
    supportsServerSide: true,
  },
  {
    platform: "Google Ads" as Platform,
    category: "Advertising" as Category,
    dataSentTo: "US",
    cookieNames: ["_gcl_au", "_gcl_aw", "_gac_"],
    hostPatterns: [
      "googleadservices.com",
      "googlesyndication.com",
      "doubleclick.net",
      "google.com/pagead",
    ],
    identifierKeys: ["gcl", "gclid", "gclsrc"],
    supportsServerSide: true,
  },
  {
    platform: "TikTok" as Platform,
    category: "Advertising" as Category,
    dataSentTo: "US/China",
    cookieNames: ["_ttp", "_tt_enable_cookie", "ttclid"],
    hostPatterns: ["tiktok.com", "analytics.tiktok.com"],
    identifierKeys: ["ttclid", "ttp"],
    supportsServerSide: true,
  },
  {
    platform: "Klaviyo" as Platform,
    category: "Advertising" as Category,
    dataSentTo: "US",
    cookieNames: ["__kla_id"],
    hostPatterns: ["klaviyo.com"],
    identifierKeys: ["kla_id", "klaviyo"],
    supportsServerSide: true,
  },
  {
    platform: "Pinterest" as Platform,
    category: "Advertising" as Category,
    dataSentTo: "US",
    cookieNames: ["_pin_unauth", "_pinterest_sess"],
    hostPatterns: ["ct.pinterest.com", "pinterest.com"],
    identifierKeys: ["epik"],
    supportsServerSide: true,
  },
  {
    platform: "Microsoft Ads" as Platform,
    category: "Advertising" as Category,
    dataSentTo: "US",
    cookieNames: ["_uetsid", "_uetvid", "MUID"],
    hostPatterns: ["bing.com", "bat.bing.com"],
    identifierKeys: ["uet", "msclkid"],
    supportsServerSide: true,
  },
];

function matchTrackerByHost(hostname: string): Platform | null {
  const h = normalizeHostname(hostname);
  for (const t of TRACKER_CATALOG) {
    if (t.hostPatterns.some((p) => h.includes(p))) return t.platform;
  }
  return null;
}

function matchTrackerByCookie(cookieName: string): Platform | null {
  for (const t of TRACKER_CATALOG) {
    if (
      t.cookieNames.some((cn) => cookieName === cn || cookieName.startsWith(cn))
    )
      return t.platform;
  }
  return null;
}

function matchTrackerByIdentifier(key: string): Platform | null {
  const lk = key.toLowerCase();
  for (const t of TRACKER_CATALOG) {
    if (t.identifierKeys.some((ik) => lk.includes(ik))) return t.platform;
  }
  return null;
}

function platformHasServerSignal(p: Platform): boolean {
  return (
    TRACKER_CATALOG.find((t) => t.platform === p)?.supportsServerSide ?? false
  );
}

// -----------------------------
// Main Audit
// -----------------------------
export async function auditSite(targetUrl: string): Promise<StapeLikeReport> {
  const browser = await chromium.launch({ headless: true });
  const startTime = Date.now();

  try {
    const context = await browser.newContext({
      userAgent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
      viewport: { width: 1920, height: 1080 },
      ignoreHTTPSErrors: false,
    });

    const page = await context.newPage();

    const requestRecords: RequestRecord[] = [];
    const hosts = new Map<string, HostStats>();

    const baseDomain = getRegistrableDomain(targetUrl);
    const isHttps = targetUrl.startsWith("https://");

    const trackingHosts = new Set<string>();
    const trackingFirstPartySubdomainHosts = new Set<string>();

    const firstPartyCollectorPOSTs: RequestRecord[] = [];
    const fpCollectorIdKeys = new Set<string>();

    page.on("request", (req: Request) => {
      const u = new URL(req.url());
      const hostname = normalizeHostname(u.hostname);
      const group = classifyHost(hostname, baseDomain);

      requestRecords.push({
        ts: Date.now(),
        url: req.url(),
        method: req.method(),
        hostname,
        path: safePath(u),
        group,
        resourceType: req.resourceType(),
      });

      const stats = getOrInitHostStats(hosts, hostname, group);
      stats.requests++;
      if (req.method() === "POST") stats.posts++;
      bump(stats.topPaths, safePath(u));

      // Track if this is a tracking subdomain making requests
      if (isTrackingSubdomain(hostname, baseDomain)) {
        trackingFirstPartySubdomainHosts.add(hostname);
      }

      const platform = matchTrackerByHost(hostname);
      if (platform) trackingHosts.add(hostname);

      // Check for first-party collector POST
      if (
        req.method() === "POST" &&
        group === "subdomain" &&
        isTrackingSubdomain(hostname, baseDomain)
      ) {
        const pd = req.postData();
        if (pd) {
          const rec = requestRecords[requestRecords.length - 1];
          rec.postDataBytes = Buffer.byteLength(pd, "utf8");

          const hits: IdentifierHit[] = [];
          for (const t of TRACKER_CATALOG) {
            for (const idKey of t.identifierKeys) {
              if (pd.toLowerCase().includes(idKey)) {
                hits.push({ key: idKey, where: "body" });
                fpCollectorIdKeys.add(idKey);
                bump(stats.identifierKeys, idKey);
              }
            }
          }
          if (hits.length > 0) {
            rec.identifierHits = hits;
            stats.identifierHits += hits.length;
            firstPartyCollectorPOSTs.push(rec);
          }
        }
      }
    });

    page.on("response", async (res: Response) => {
      const u = new URL(res.url());
      const hostname = normalizeHostname(u.hostname);
      const group = classifyHost(hostname, baseDomain);
      const stats = getOrInitHostStats(hosts, hostname, group);

      const idx = requestRecords.findIndex((r) => r.url === res.url());
      if (idx >= 0) {
        requestRecords[idx].status = res.status();
        requestRecords[idx].ok = res.ok();
      }

      const setCookieHeaders = res.headers()["set-cookie"];
      if (setCookieHeaders) {
        stats.setCookieResponses++;
        const lines = splitSetCookie(setCookieHeaders);
        stats.setCookieCount += lines.length;
        for (const line of lines) {
          const name = extractCookieName(line);
          if (name) {
            bump(stats.cookieNames, name);

            // Track if this response is from a tracking subdomain
            if (isTrackingSubdomain(hostname, baseDomain)) {
              trackingFirstPartySubdomainHosts.add(hostname);
            }
          }
        }
        if (idx >= 0) {
          requestRecords[idx].setCookieNames = lines
            .map(extractCookieName)
            .filter(Boolean) as string[];
          requestRecords[idx].setCookieCount = lines.length;
        }
      }
    });

    await page.goto(targetUrl, { waitUntil: "networkidle", timeout: 45000 });
    const loadTimeMS = Date.now() - startTime;

    const browserCookies = await context.cookies();

    // -----------------------------
    // COOKIE ANALYSIS (TRACKING-ONLY)
    // -----------------------------
    const trackingCookies: ReportCookieRow[] = [];

    for (const c of browserCookies) {
      const platform = matchTrackerByCookie(c.name);
      if (!platform) continue;

      const catalogEntry = TRACKER_CATALOG.find((t) => t.platform === platform);
      if (!catalogEntry) continue;

      const cookieDomain = normalizeHostname(c.domain);

      // FIXED: Check if this cookie was set by a tracking subdomain
      const party: CookieParty = isFirstPartyTrackingCookie(
        cookieDomain,
        baseDomain,
        trackingFirstPartySubdomainHosts,
      )
        ? "firstParty"
        : "thirdParty";

      const lifetimeDays = daysFromCookieExpires(c.expires);

      const secure = Boolean(c.secure);
      const sameSite = c.sameSite ? String(c.sameSite).toLowerCase() : null;
      const httpOnly = Boolean(c.httpOnly);
      const insecure =
        !secure || (!httpOnly && sameSite !== "strict" && sameSite !== "lax");

      const setByServer = Boolean((c as any).setByServer);

      trackingCookies.push({
        name: c.name,
        provider: catalogEntry.platform,
        category: catalogEntry.category,
        dataSentTo: catalogEntry.dataSentTo,
        lifetimeDays,
        party,
        setMethod: setByServer ? "server" : "client",
        domain: cookieDomain,
        secure,
        sameSite,
        httpOnly,
        insecure,
      });
    }

    const uniqueTrackingCookies = uniq(trackingCookies.map((c) => c.name)).map(
      (name) => trackingCookies.find((c) => c.name === name)!,
    );

    const fpTrackingCookies = uniqueTrackingCookies.filter(
      (c) => c.party === "firstParty",
    );
    const tpTrackingCookies = uniqueTrackingCookies.filter(
      (c) => c.party === "thirdParty",
    );
    const serverSetTrackingCookies = uniqueTrackingCookies.filter(
      (c) => c.setMethod === "server",
    );
    const insecureTrackingCookies = uniqueTrackingCookies.filter(
      (c) => c.insecure,
    );

    // -----------------------------
    // TRACKER DETECTION
    // -----------------------------
    const trackersDetected: TrackerRow[] = [];

    for (const entry of TRACKER_CATALOG) {
      const matchedCookies = uniqueTrackingCookies
        .filter((c) => c.provider === entry.platform)
        .map((c) => c.name);

      const matchedHosts = Array.from(trackingHosts).filter(
        (h) => matchTrackerByHost(h) === entry.platform,
      );

      const fpPosts = firstPartyCollectorPOSTs.filter((post) =>
        post.identifierHits?.some((hit) =>
          entry.identifierKeys.includes(hit.key),
        ),
      ).length;

      if (
        matchedCookies.length === 0 &&
        matchedHosts.length === 0 &&
        fpPosts === 0
      )
        continue;

      const hasServerSide = fpPosts > 0;
      const hasCookies = matchedCookies.length > 0;

      const trackingMethod: TrackingMethod =
        hasServerSide && hasCookies
          ? "Client & Server-side"
          : hasServerSide
            ? "Server-side"
            : "Client-side";

      const supportsServerSide = entry.supportsServerSide;
      const status: TrackerStatus =
        hasServerSide || !supportsServerSide
          ? "All good"
          : hasCookies
            ? "Improve"
            : "Not supported";

      trackersDetected.push({
        platform: entry.platform,
        category: entry.category,
        dataSentTo: entry.dataSentTo,
        trackingMethod,
        status,
        evidence: {
          cookiesMatched: matchedCookies,
          requestHostsMatched: matchedHosts,
          firstPartyRoutedCollectorPosts: fpPosts,
        },
      });
    }

    // -----------------------------
    // SCORING
    // -----------------------------
    const pageSpeed = (async () => {
      const timeThreshold = 3000;
      const sizeThreshold = 2000;

      let score = 100;

      if (loadTimeMS > timeThreshold) {
        const penalty = Math.min(
          40,
          Math.round(((loadTimeMS - timeThreshold) / 1000) * 10),
        );
        score -= penalty;
      }

      const transferKB = Math.round((await page.content()).length / 1024);
      if (transferKB > sizeThreshold) {
        const penalty = Math.min(
          30,
          Math.round(((transferKB - sizeThreshold) / 500) * 5),
        );
        score -= penalty;
      }

      return clamp(score, 0, 100);
    })();

    const cookieLifetime = (() => {
      if (!uniqueTrackingCookies.length) return 0;

      let score = 70;

      const longLived = uniqueTrackingCookies.filter(
        (c) => (c.lifetimeDays ?? 0) >= 90,
      ).length;
      score += Math.min(20, longLived * 5);

      const shortLived = uniqueTrackingCookies.filter(
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
      if (!uniqueTrackingCookies.length) return 0;

      const fpRatio = ratio(
        fpTrackingCookies.length,
        uniqueTrackingCookies.length,
      );
      const tpRatio = ratio(
        tpTrackingCookies.length,
        uniqueTrackingCookies.length,
      );

      const insecureRatio = ratio(
        insecureTrackingCookies.length,
        uniqueTrackingCookies.length,
      );

      const shortOrUnknown = uniqueTrackingCookies.filter(
        (c) => c.lifetimeDays === null || (c.lifetimeDays ?? 0) < 7,
      ).length;
      const shortRatio = ratio(shortOrUnknown, uniqueTrackingCookies.length);

      let score = 0;

      // main driver: first-party tracking coverage
      score += fpRatio * 90;

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

      const cookieRows = uniqueTrackingCookies.filter((c) => c.provider === p);
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
      const gaCookies = uniqueTrackingCookies.filter(
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
    let overall = cookieScore;

    // Page speed only matters when it's bad
    const SPEED_FLOOR = 40; // start penalizing below this
    const PENALTY_PER_POINT = 0.5; // tune aggressiveness
    const MAX_SPEED_PENALTY = 20; // cap so speed never dominates

    if ((await pageSpeed) < SPEED_FLOOR) {
      const penalty = Math.min(
        MAX_SPEED_PENALTY,
        Math.round((SPEED_FLOOR - (await pageSpeed)) * PENALTY_PER_POINT),
      );
      overall -= penalty;
    }

    // Optional: reward real first-party routing / server-side signal
    if (platforms.googleAds.serverSide || platforms.meta.serverSide) {
      overall += 5;
    }

    overall = clamp(Math.round(overall), 0, 100);

    // Hard rule: no first-party tracking = capped score
    if (fpTrackingCookies.length === 0) {
      overall = Math.min(overall, 50);
    }

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
        pageSpeed: Math.round(await pageSpeed),
      },
      platforms,
      cookies: {
        total: uniqueTrackingCookies.length,
        firstParty: fpTrackingCookies.length,
        thirdParty: tpTrackingCookies.length,
        serverSet: serverSetTrackingCookies.length,
        insecure: insecureTrackingCookies.length,
        trackingCookies: uniqueTrackingCookies.sort((a, b) =>
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
          serverSet: browserCookies.filter((c) =>
            Boolean((c as any).setByServer),
          ).length,
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
