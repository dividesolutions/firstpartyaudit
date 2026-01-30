// audit.ts
import {
  chromium,
  type Browser,
  type Page,
  type Request,
  type Response,
} from "playwright";
import { parse as parseTld } from "tldts";

/**
 * First-party SST audit (transport-first)
 *
 * Server-side tracking is defined by who sends the event to the platform.
 * This scanner focuses on TRANSPORT evidence:
 *  - Browser -> first-party collector (root/subdomain) POSTs with analytics-like payloads
 *  - Browser -> direct platform collection endpoints (Meta/GA/Ads/TikTok)
 *
 * Cookies are NOT used for scoring/truth. We only keep one cookie signal:
 *  - Are cookies being set by a subdomain (via Set-Cookie on subdomain responses)?
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

  // cookie signal only (no scoring, no lifetime parsing)
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
    // Direct platform collection observed in the browser
    directPlatformEvidence: PlatformEvidence;

    // First-party collector observed (browser -> root/subdomain)
    firstPartyCollectorEvidence: {
      hasCollectorPost: boolean;
      collectorHosts: string[];
      collectorPostCount: number;
      collectorAnalyticsLikePostCount: number;
    };

    // Simple cookie hint: Set-Cookie seen from subdomain responses
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

// Query/body keys that commonly appear in tracking payloads (not proof, just helps detect "analytics-like")
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

// Paths that often indicate a first-party collector endpoint on YOUR infra.
// (Still not proof of server-side forwarding; we require transport gating vs direct platform collectors.)
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

// Known direct platform collection hosts (browser -> platform).
// Seeing these strongly suggests client-side transport is happening.
type PlatformFlag = "ga" | "meta" | "googleAds" | "tiktok";

const DIRECT_PLATFORM_HOST_PATTERNS: {
  name: PlatformFlag;
  re: RegExp;
}[] = [
  { name: "ga", re: /(^|\.)google-analytics\.com$/i },
  { name: "ga", re: /(^|\.)analytics\.google\.com$/i },
  { name: "ga", re: /(^|\.)googletagmanager\.com$/i },
  { name: "googleAds", re: /(^|\.)googleadservices\.com$/i },
  { name: "googleAds", re: /(^|\.)doubleclick\.net$/i },
  { name: "meta", re: /(^|\.)facebook\.com$/i },
  { name: "meta", re: /(^|\.)connect\.facebook\.net$/i },
  { name: "tiktok", re: /(^|\.)tiktok\.com$/i },
  { name: "tiktok", re: /(^|\.)tiktokcdn\.com$/i },
];

// Paths that are strong indicators of direct platform collection (heuristic reinforcement)
const DIRECT_PLATFORM_PATH_HINTS: RegExp[] = [
  /\/collect/i,
  /\/g\/collect/i,
  /\/mp\/collect/i,
  /\/tr\/?/i, // facebook.com/tr
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

  // If the path looks like a collector endpoint, we’ll inspect body
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

  // reinforce: if host matches AND path looks like a collection endpoint, it’s even stronger,
  // but we still treat host match alone as “direct platform present” because tags often load there.
  const hasPathCollect = DIRECT_PLATFORM_PATH_HINTS.some((re) =>
    re.test(urlLower),
  );
  if (!hasPathCollect) return out;

  return out;
}

// Parse "Set-Cookie" header into cookie names.
// Note: Set-Cookie is special; multiple headers are possible.
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

// best-effort count of cookies in a set-cookie string
function countSetCookie(setCookieHeader: string | string[]): number {
  if (Array.isArray(setCookieHeader)) return setCookieHeader.length;

  // A single string can contain multiple cookies in some environments.
  // This split is best-effort and not perfect for all edge cases, but OK for signal.
  return setCookieHeader.split(/,(?=[^;]+=[^;]+)/).length;
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

  // direct platform evidence (browser -> platform)
  let directPlatform: PlatformEvidence = {
    ga: false,
    meta: false,
    googleAds: false,
    tiktok: false,
    other: [],
  };

  // first-party collector evidence (browser -> root/subdomain)
  const collectorHosts = new Set<string>();
  let collectorPostCount = 0;
  let collectorAnalyticsLikePostCount = 0;

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

    // Ensure host entry exists
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

    // Capture Set-Cookie headers (cookie signal only)
    page.on("response", async (res: Response) => {
      const req = res.request();
      const reqUrl = req.url();
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
      for (const n of names) {
        hs.cookieNames[n] = (hs.cookieNames[n] || 0) + 1;
      }

      if (group === "subdomain") {
        subdomainCookieHosts.add(hostname);
        subdomainSetCookieCount += count;
        for (const n of names) {
          subdomainCookieNames[n] = (subdomainCookieNames[n] || 0) + 1;
        }
      }
    });

    // Capture requests (transport evidence)
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

      // Direct platform evidence
      const dp = isDirectPlatformHit(hostname, urlLower);
      directPlatform = {
        ga: directPlatform.ga || dp.ga,
        meta: directPlatform.meta || dp.meta,
        googleAds: directPlatform.googleAds || dp.googleAds,
        tiktok: directPlatform.tiktok || dp.tiktok,
        other: Array.from(new Set([...directPlatform.other, ...dp.other])),
      };

      // First-party collector evidence (browser -> root/subdomain)
      const isFirstParty = group === "root" || group === "subdomain";
      const isCollectorPath = COLLECTOR_PATH_HINTS.some((re) =>
        re.test(urlLower),
      );
      const isCollectorPost =
        isFirstParty && method.toUpperCase() === "POST" && isCollectorPath;

      if (isCollectorPost) {
        collectorHosts.add(hostname);
        collectorPostCount += 1;
        if (analyticsLike) {
          collectorAnalyticsLikePostCount += 1;
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

    // Let late beacons fire a bit
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

    let classification: AuditResult["classification"] = "clientSideOnly";

    if (hasCollectorPost && !hasDirectPlatform) {
      // strongest browser-side signal that events are not being sent directly to platforms
      classification = hasSubdomainSetCookie
        ? "serverSideManaged"
        : "serverSideLikely";
    } else if (hasCollectorPost && hasDirectPlatform) {
      // could be client relay, hybrid, or partial SST
      classification = "fpRelayClient";
    } else {
      classification = "clientSideOnly";
    }

    // -----------------------------
    // Scores (simple + aligned to your definition)
    // -----------------------------
    // Analytics score: reward collector transport + penalize direct GA collection
    const analyticsScore = (() => {
      let s = 0;

      if (hasCollectorPost) s += 70;
      if (collectorAnalyticsLikePostCount > 0) s += 15;

      if (directPlatform.ga) s -= 35;

      // small bonus for “managed infra” hint (subdomain sets cookies)
      if (hasSubdomainSetCookie) s += 5;

      return score100(s);
    })();

    // Ads score: reward collector transport + penalize direct ad platform collection
    const adsScore = (() => {
      let s = 0;

      if (hasCollectorPost) s += 70;
      if (collectorAnalyticsLikePostCount > 0) s += 10;

      // penalize any direct ad collectors in browser
      if (directPlatform.meta) s -= 25;
      if (directPlatform.googleAds) s -= 25;
      if (directPlatform.tiktok) s -= 25;

      if (hasSubdomainSetCookie) s += 5;

      return score100(s);
    })();

    // Page speed: intentionally light touch (you said it barely matters unless terrible)
    const pageSpeedScore = (() => {
      // 0-100 where very slow loads get punished, normal loads mostly fine
      if (loadMs <= 1500) return 100;
      if (loadMs <= 3000) return 90;
      if (loadMs <= 6000) return 75;
      if (loadMs <= 10000) return 55;
      return 35;
    })();

    // Overall: mostly transport evidence, tiny nudge from “managed” cookie signal and page speed
    const overallScore = (() => {
      const transportCore = Math.round(0.52 * analyticsScore + 0.48 * adsScore);
      const managedNudge = hasSubdomainSetCookie ? 3 : 0; // intentionally small
      const speedNudge = Math.round((pageSpeedScore - 80) * 0.05); // tiny influence
      return score100(transportCore + managedNudge + speedNudge);
    })();

    // Requests summary
    const totalReq = requestRecords.length;
    const fpReq = requestRecords.filter(
      (r) => r.group === "root" || r.group === "subdomain",
    ).length;
    const tpReq = totalReq - fpReq;

    // Notes
    if (!hasCollectorPost) {
      debugNotes.push(
        "No first-party collector POSTs detected (browser -> your root/subdomain).",
      );
    } else {
      debugNotes.push(
        `Detected ${collectorPostCount} first-party collector POST(s) across: ${Array.from(
          collectorHosts,
        ).join(", ")}`,
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
        `Direct platform traffic detected in browser: ${direct || "Other"}.`,
      );
    } else {
      debugNotes.push(
        "No direct platform collection hosts detected in the browser.",
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
        pageSpeed: pageSpeedScore,
      },
      evidence: {
        directPlatformEvidence: directPlatform,
        firstPartyCollectorEvidence: {
          hasCollectorPost,
          collectorHosts: Array.from(collectorHosts),
          collectorPostCount,
          collectorAnalyticsLikePostCount,
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
