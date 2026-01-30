// audit.ts
import {
  chromium,
  type Browser,
  type Request,
  type Response,
} from "playwright";
import { parse as parseTld } from "tldts";

/**
 * First-party SST audit (transport-first, SST points must be earned)
 *
 * Key product rule:
 * - A site should NOT be punished for having GA/Meta/etc.
 * - A site ONLY earns points when we see credible SST transport signals:
 *   - Browser -> FIRST-PARTY SUBDOMAIN collector POSTs
 *   - AND at least one looks like a tracking payload (analytics-like)
 *
 * Why this matters:
 * - Avoid false positives from random root-domain POSTs (cart, search, forms, etc.)
 * - Big points should only unlock when SST is actually present.
 *
 * Cookies:
 * - Not used for truth. Only keep "subdomain sets cookies" as a small infra hint.
 */

// -----------------------------
// Types
// -----------------------------
type HostGroup = "root" | "subdomain" | "thirdParty";

type PlatformEvidence = {
  ga: boolean;
  meta: boolean;
  googleAds: boolean;
  tiktok: boolean;
  other: string[];
};

type RequestRecord = {
  url: string;
  method: string;
  hostname: string;
  group: HostGroup;
  resourceType: string;
  postDataBytes: number;
  looksLikeAnalyticsPayload: boolean;
  status?: number;
  contentType?: string;
};

type HostStats = {
  hostname: string;
  group: HostGroup;
  requests: number;
  posts: number;
  analyticsLikePosts: number;

  setCookieResponses: number;
  setCookieCount: number;
  cookieNames: Record<string, number>;
};

type AuditResult = {
  url: string;
  baseDomain: string;

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
  };

  evidence: {
    directPlatformEvidence: PlatformEvidence;

    firstPartyCollectorEvidence: {
      hasCollectorPost: boolean;
      collectorHosts: string[];
      collectorPostCount: number;
      collectorAnalyticsLikePostCount: number;

      // NEW: subdomain-only collector evidence (this is what drives score)
      hasSubdomainCollectorPost: boolean;
      subdomainCollectorHosts: string[];
      subdomainCollectorPostCount: number;
      subdomainCollectorAnalyticsLikePostCount: number;
    };

    subdomainCookieSignal: {
      hasSubdomainSetCookie: boolean;
      subdomainHostsSettingCookies: string[];
      subdomainSetCookieCount: number;
      cookieNames: Record<string, number>;
    };
  };

  requests: {
    total: number;
    firstParty: number;
    thirdParty: number;
    hosts: HostStats[];
  };

  debug: {
    notes: string[];
    loadMs: number;
  };
};

// -----------------------------
// Heuristics / patterns
// -----------------------------
const ANALYTICS_BODY_HINTS = [
  "event",
  "events",
  "client_id",
  "cid",
  "measurement_id",
  "tid",
  "pixel_id",
  "fbp",
  "fbc",
  "page_location",
  "page_referrer",
  "user_agent",
];

const COLLECTOR_PATH_HINTS: RegExp[] = [
  /\/collect/i,
  /\/g\/collect/i,
  /\/mp\/collect/i,
  /\/collector/i,
  /\/events?/i,
  /\/event/i,
  /\/track/i,
  /\/tracking/i,
  /\/analytics/i,
  /\/beacon/i,
  /\/capi/i,
];

type PlatformFlag = "ga" | "meta" | "googleAds" | "tiktok";

const DIRECT_PLATFORM_HOST_PATTERNS: { name: PlatformFlag; re: RegExp }[] = [
  { name: "ga", re: /(^|\.)google-analytics\.com$/i },
  { name: "ga", re: /(^|\.)analytics\.google\.com$/i },
  { name: "ga", re: /(^|\.)googletagmanager\.com$/i },
  { name: "ga", re: /(^|\.)g\.doubleclick\.net$/i },

  { name: "googleAds", re: /(^|\.)googleadservices\.com$/i },
  { name: "googleAds", re: /(^|\.)doubleclick\.net$/i },

  { name: "meta", re: /(^|\.)facebook\.com$/i },
  { name: "meta", re: /(^|\.)connect\.facebook\.net$/i },

  { name: "tiktok", re: /(^|\.)tiktok\.com$/i },
  { name: "tiktok", re: /(^|\.)tiktokcdn\.com$/i },
];

const DIRECT_PLATFORM_PATH_HINTS: RegExp[] = [
  /\/collect/i,
  /\/g\/collect/i,
  /\/mp\/collect/i,
  /\/tr\/?/i,
  /\/events/i,
  /\/conversion/i,
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

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function score100(n: number): number {
  return Math.round(clamp(n, 0, 100));
}

function looksAnalyticsLike(
  reqUrl: string,
  method: string,
  postData: string | null,
): boolean {
  const url = (reqUrl || "").toLowerCase();
  if (method.toUpperCase() !== "POST") return false;

  const hasPathHint = COLLECTOR_PATH_HINTS.some((re) => re.test(url));
  if (!hasPathHint) return false;

  const body = (postData || "").toLowerCase();
  if (!body) return false;

  return ANALYTICS_BODY_HINTS.some((k) => body.includes(k));
}

function isDirectPlatformHit(
  hostname: string,
  urlLower: string,
): PlatformEvidence {
  const h = normalizeHostname(hostname);
  const out: PlatformEvidence = {
    ga: false,
    meta: false,
    googleAds: false,
    tiktok: false,
    other: [],
  };

  for (const p of DIRECT_PLATFORM_HOST_PATTERNS) {
    if (p.re.test(h)) out[p.name] = true;
  }

  // keep for future expansion (right now "other" isn't populated)
  const hasPathCollect = DIRECT_PLATFORM_PATH_HINTS.some((re) =>
    re.test(urlLower),
  );
  if (!hasPathCollect) return out;

  return out;
}

function extractCookieNamesFromSetCookie(
  setCookieHeader: string | string[],
): string[] {
  const raw = Array.isArray(setCookieHeader)
    ? setCookieHeader
    : [setCookieHeader];
  const names: string[] = [];
  for (const line of raw) {
    const firstPart = line.split(";")[0];
    const eq = firstPart.indexOf("=");
    if (eq > 0) {
      const name = firstPart.slice(0, eq).trim();
      if (name) names.push(name);
    }
  }
  return names;
}

function countSetCookie(setCookieHeader: string | string[]): number {
  if (Array.isArray(setCookieHeader)) return setCookieHeader.length;
  return setCookieHeader.split(/,(?=[^;]+=[^;]+)/).length;
}

// -----------------------------
// Scoring (BigDill should be ~25 without SST)
// -----------------------------
const BASELINE_BAD_NO_SST = 25;

// SST unlock requires SUBDOMAIN + analytics-like evidence
const BONUS_SST_UNLOCK = 55; // big jump when real SST is detected
const BONUS_MORE_EVENTS = 10; // multiple analytics-like events
const BONUS_COLLECTOR_ONLY = 5; // small extra credit if routed (no direct platform)
const BONUS_SUBDOMAIN_SET_COOKIE = 3; // tiny infra hint

function pageSpeedScore(loadMs: number): number {
  if (loadMs <= 1500) return 100;
  if (loadMs <= 3000) return 92;
  if (loadMs <= 6000) return 80;
  if (loadMs <= 10000) return 65;
  return 45;
}

function pageSpeedNudge(ps: number): number {
  // tiny influence only
  return Math.round((ps - 80) * 0.05);
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

  const requestRecords: RequestRecord[] = [];
  const hostMap = new Map<string, HostStats>();

  let directPlatform: PlatformEvidence = {
    ga: false,
    meta: false,
    googleAds: false,
    tiktok: false,
    other: [],
  };

  // Root+subdomain collector evidence (kept for debugging)
  const collectorHosts = new Set<string>();
  let collectorPostCount = 0;
  let collectorAnalyticsLikePostCount = 0;

  // ✅ NEW: SUBDOMAIN-only collector evidence (this drives the score)
  const subdomainCollectorHosts = new Set<string>();
  let subdomainCollectorPostCount = 0;
  let subdomainCollectorAnalyticsLikePostCount = 0;

  // cookie signal: which subdomains set cookies
  const subdomainCookieHosts = new Set<string>();
  let subdomainSetCookieCount = 0;
  const subdomainCookieNames: Record<string, number> = {};

  const debugNotes: string[] = [];
  let loadMs = 0;

  try {
    browser = await chromium.launch({ headless });
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      userAgent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    });

    const page = await context.newPage();

    function ensureHost(hostname: string, group: HostGroup): HostStats {
      const existing = hostMap.get(hostname);
      if (existing) return existing;
      const hs: HostStats = {
        hostname,
        group,
        requests: 0,
        posts: 0,
        analyticsLikePosts: 0,
        setCookieResponses: 0,
        setCookieCount: 0,
        cookieNames: {},
      };
      hostMap.set(hostname, hs);
      return hs;
    }

    // Cookie signal only
    page.on("response", async (res: Response) => {
      const reqUrl = res.request().url();
      let hostname = "";
      try {
        hostname = normalizeHostname(new URL(reqUrl).hostname);
      } catch {
        return;
      }

      const group = groupHost(hostname, baseDomain);
      const hs = ensureHost(hostname, group);

      const headers = await res.headers();
      const setCookie = headers["set-cookie"];
      if (!setCookie) return;

      const count = countSetCookie(setCookie);
      const names = extractCookieNamesFromSetCookie(setCookie);

      hs.setCookieResponses += 1;
      hs.setCookieCount += count;
      for (const n of names) hs.cookieNames[n] = (hs.cookieNames[n] || 0) + 1;

      if (group === "subdomain") {
        subdomainCookieHosts.add(hostname);
        subdomainSetCookieCount += count;
        for (const n of names)
          subdomainCookieNames[n] = (subdomainCookieNames[n] || 0) + 1;
      }
    });

    // Transport evidence
    page.on("request", (req: Request) => {
      const reqUrl = req.url();
      const method = req.method();
      const resourceType = req.resourceType();
      const postData = req.postData() || "";
      const postDataBytes = postData ? Buffer.byteLength(postData, "utf8") : 0;

      let hostname = "";
      try {
        hostname = normalizeHostname(new URL(reqUrl).hostname);
      } catch {
        hostname = "";
      }

      const group = hostname ? groupHost(hostname, baseDomain) : "thirdParty";
      const hs = hostname ? ensureHost(hostname, group) : null;

      if (hs) {
        hs.requests += 1;
        if (method.toUpperCase() === "POST") hs.posts += 1;
      }

      const urlLower = reqUrl.toLowerCase();
      const analyticsLike = looksAnalyticsLike(reqUrl, method, postData);

      // Direct platform evidence (neutral for score; affects classification/bonuses only)
      const dp = isDirectPlatformHit(hostname, urlLower);
      directPlatform = {
        ga: directPlatform.ga || dp.ga,
        meta: directPlatform.meta || dp.meta,
        googleAds: directPlatform.googleAds || dp.googleAds,
        tiktok: directPlatform.tiktok || dp.tiktok,
        other: Array.from(new Set([...directPlatform.other, ...dp.other])),
      };

      // Collector candidate: first-party POST to collector-ish path
      const isFirstParty = group === "root" || group === "subdomain";
      const isCollectorPath = COLLECTOR_PATH_HINTS.some((re) =>
        re.test(urlLower),
      );
      const isCollectorPost =
        isFirstParty && method.toUpperCase() === "POST" && isCollectorPath;

      if (isCollectorPost) {
        collectorHosts.add(hostname);
        collectorPostCount += 1;
        if (analyticsLike) collectorAnalyticsLikePostCount += 1;
      }

      // ✅ SUBDOMAIN-only collector evidence (this is what we trust)
      const isSubdomainCollectorPost =
        group === "subdomain" &&
        method.toUpperCase() === "POST" &&
        isCollectorPath;
      if (isSubdomainCollectorPost) {
        subdomainCollectorHosts.add(hostname);
        subdomainCollectorPostCount += 1;

        if (analyticsLike) {
          subdomainCollectorAnalyticsLikePostCount += 1;
          if (hs) hs.analyticsLikePosts += 1;
        }
      }

      requestRecords.push({
        url: reqUrl,
        method,
        hostname,
        group,
        resourceType,
        postDataBytes,
        looksLikeAnalyticsPayload: analyticsLike,
      });
    });

    // Navigate
    const start = Date.now();
    await page.goto(targetUrl, { waitUntil: "load", timeout: timeoutMs });
    loadMs = Date.now() - start;

    // Let late beacons fire
    await page.waitForTimeout(2500);

    // -----------------------------
    // Classification (transport-first)
    // -----------------------------
    const hasCollectorPost = collectorPostCount > 0;

    const hasDirectPlatform =
      directPlatform.ga ||
      directPlatform.meta ||
      directPlatform.googleAds ||
      directPlatform.tiktok ||
      (directPlatform.other?.length ?? 0) > 0;

    const hasSubdomainSetCookie = subdomainCookieHosts.size > 0;

    // SST-worthy condition (the one that should move scores)
    const hasSstSignal =
      subdomainCollectorAnalyticsLikePostCount > 0 &&
      subdomainCollectorHosts.size > 0;

    let classification: AuditResult["classification"] = "clientSideOnly";

    if (hasSstSignal && !hasDirectPlatform) {
      classification = hasSubdomainSetCookie
        ? "serverSideManaged"
        : "serverSideLikely";
    } else if (hasSstSignal && hasDirectPlatform) {
      classification = "fpRelayClient"; // hybrid / partial
    } else {
      classification = "clientSideOnly";
    }

    // -----------------------------
    // Scores (BigDill ~25 without SST)
    // -----------------------------
    //
    // Important: we do NOT give SST points unless hasSstSignal is true.
    // GA/Meta/etc are neutral.
    //
    const ps = pageSpeedScore(loadMs);

    const collectorOnlyForAnalytics = hasSstSignal && !directPlatform.ga;
    const collectorOnlyForAds =
      hasSstSignal &&
      !directPlatform.meta &&
      !directPlatform.googleAds &&
      !directPlatform.tiktok;

    const analyticsScore = (() => {
      let s = BASELINE_BAD_NO_SST;

      if (hasSstSignal) {
        s += BONUS_SST_UNLOCK;

        if (subdomainCollectorAnalyticsLikePostCount >= 3)
          s += BONUS_MORE_EVENTS;

        if (collectorOnlyForAnalytics) s += BONUS_COLLECTOR_ONLY;

        if (hasSubdomainSetCookie) s += BONUS_SUBDOMAIN_SET_COOKIE;
      }

      return score100(s);
    })();

    const adsScore = (() => {
      let s = BASELINE_BAD_NO_SST;

      if (hasSstSignal) {
        s += BONUS_SST_UNLOCK;

        if (subdomainCollectorAnalyticsLikePostCount >= 3)
          s += BONUS_MORE_EVENTS;

        if (collectorOnlyForAds) s += BONUS_COLLECTOR_ONLY;

        if (hasSubdomainSetCookie) s += BONUS_SUBDOMAIN_SET_COOKIE;
      }

      return score100(s);
    })();

    const overallScore = (() => {
      const transportCore = Math.round(0.52 * analyticsScore + 0.48 * adsScore);
      const speed = pageSpeedNudge(ps);
      return score100(transportCore + speed);
    })();

    // Requests summary
    const totalReq = requestRecords.length;
    const fpReq = requestRecords.filter(
      (r) => r.group === "root" || r.group === "subdomain",
    ).length;
    const tpReq = totalReq - fpReq;

    // Notes (clear explanation for cases like BigDill)
    if (!hasSstSignal) {
      debugNotes.push(
        "No SST signal detected: no analytics-like collector POSTs to a first-party SUBDOMAIN.",
      );
      debugNotes.push(
        "Root-domain POSTs are ignored for SST scoring to avoid false positives (cart/forms/etc).",
      );
      debugNotes.push(
        "Direct platform tags (GA/Meta/Ads) are neutral; you just don't earn SST points without a subdomain collector.",
      );
    } else {
      debugNotes.push(
        `SST signal detected: ${subdomainCollectorAnalyticsLikePostCount} analytics-like collector POST(s) to subdomain(s): ${Array.from(
          subdomainCollectorHosts,
        ).join(", ")}`,
      );
    }

    if (hasCollectorPost && !hasSstSignal) {
      debugNotes.push(
        `Note: saw ${collectorPostCount} first-party collector-ish POST(s) (root/subdomain), but none qualified as SST (subdomain + analytics-like).`,
      );
      debugNotes.push(
        `Collector-ish hosts seen (debug): ${Array.from(collectorHosts).join(", ")}`,
      );
    }

    if (hasDirectPlatform) {
      const direct = [
        directPlatform.ga ? "GA" : null,
        directPlatform.meta ? "Meta" : null,
        directPlatform.googleAds ? "Google Ads" : null,
        directPlatform.tiktok ? "TikTok" : null,
      ]
        .filter(Boolean)
        .join(", ");
      debugNotes.push(
        `Direct platform traffic detected in browser: ${direct || "Other"}. (Neutral)`,
      );
    }

    if (hasSubdomainSetCookie) {
      debugNotes.push(
        `Subdomain Set-Cookie observed from: ${Array.from(subdomainCookieHosts).join(", ")}`,
      );
    }

    return {
      url: targetUrl,
      baseDomain,
      classification,
      scores: {
        overall: overallScore,
        analytics: analyticsScore,
        ads: adsScore,
        pageSpeed: ps,
      },
      evidence: {
        directPlatformEvidence: directPlatform,
        firstPartyCollectorEvidence: {
          hasCollectorPost,
          collectorHosts: Array.from(collectorHosts),
          collectorPostCount,
          collectorAnalyticsLikePostCount,

          hasSubdomainCollectorPost: subdomainCollectorPostCount > 0,
          subdomainCollectorHosts: Array.from(subdomainCollectorHosts),
          subdomainCollectorPostCount,
          subdomainCollectorAnalyticsLikePostCount,
        },
        subdomainCookieSignal: {
          hasSubdomainSetCookie,
          subdomainHostsSettingCookies: Array.from(subdomainCookieHosts),
          subdomainSetCookieCount,
          cookieNames: subdomainCookieNames,
        },
      },
      requests: {
        total: totalReq,
        firstParty: fpReq,
        thirdParty: tpReq,
        hosts: Array.from(hostMap.values()).sort(
          (a, b) => b.requests - a.requests,
        ),
      },
      debug: {
        notes: debugNotes,
        loadMs,
      },
    };
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}
