// src/audit.ts
import {
  chromium,
  type Browser,
  type Request,
  type Response,
} from "playwright";
import { parse as parseTld } from "tldts";

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
type SetterGroup = "root" | "subdomain" | "thirdParty" | "unknown";

type PlatformCookieStats = {
  total: number;

  // Scope (cookie.domain based)
  scope: {
    firstParty: number;
    thirdParty: number;
  };

  // How it was set (best effort)
  setMethod: {
    server: number; // correlated via Set-Cookie
    client: number; // no server correlation found
  };

  // Who set it (only meaningful when server-set)
  serverSetterGroup: Record<SetterGroup, number>;

  // Your key signals
  firstPartyServerSet: number; // server-set by root/subdomain
  firstPartyTrackingSubdomainServerSet: number; // server-set by tracking subdomain only

  insecure: number;

  // Debug context (kept small)
  uniqueCookieNames: number;
  topCookieNames: Array<{ name: string; count: number }>;
  domains: {
    firstParty: string[];
    thirdParty: string[];
  };
  serverSetByHosts: {
    root: string[];
    subdomain: string[];
    thirdParty: string[];
  };
};

// Lowercases and strips www.
function normalizeHostname(hostname: string): string {
  let h = (hostname || "").trim().toLowerCase();
  if (h.startsWith("www.")) h = h.slice(4);
  return h;
}

// Gets the registrable domain (eTLD+1) for a given URL
function getRegistrableDomain(targetUrl: string): string {
  const u = new URL(targetUrl);
  const parsed = parseTld(u.hostname);
  return normalizeHostname(parsed.domain ?? u.hostname);
}

// Classifies a hostname as root/subdomain/thirdParty relative to a registrable domain
function classifyHost(hostname: string, registrableDomain: string): HostGroup {
  const h = normalizeHostname(hostname);
  const rd = normalizeHostname(registrableDomain);

  if (h === rd) return "root";
  if (h.endsWith("." + rd)) return "subdomain";
  return "thirdParty";
}

// Counter increment for stat maps
function bump(obj: Record<string, number>, key: string, inc = 1) {
  obj[key] = (obj[key] ?? 0) + inc;
}

// Retrieves existing or initializes new HostStats entry
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

/**
 * Split Set-Cookie safely:
 * - Sometimes comes as one combined string (comma-delimited)
 * - Sometimes comes as multiple headers/values
 */
// Regex to split Set-Cookie headers correctly
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

function uniqPush(arr: string[], value: string, limit = 8) {
  const v = String(value || "").trim();
  if (!v) return;
  if (arr.includes(v)) return;
  if (arr.length >= limit) return;
  arr.push(v);
}

function topN(map: Record<string, number>, n = 6) {
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([name, count]) => ({ name, count }));
}

// List of common advertising/analytics identifiers
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

// Detects the presence of keys (never stores values)
function scanForIdentifiers(opts: {
  url: URL;
  method: string;
  headers: Record<string, string>;
  postData?: string | null;
  cookieNamesFromResponse?: string[];
}): IdentifierHit[] {
  const hits: IdentifierHit[] = [];
  const { url, headers, postData, cookieNamesFromResponse } = opts;

  // URL query params
  for (const [k] of url.searchParams.entries()) {
    const key = k.toLowerCase();
    if (IDENTIFIER_KEYS.includes(key)) hits.push({ key, where: "url" });
  }

  // Headers (best effort)
  for (const [hk, hv] of Object.entries(headers)) {
    const hKey = hk.toLowerCase();
    const hVal = (hv ?? "").toLowerCase();
    for (const idKey of IDENTIFIER_KEYS) {
      if (hKey.includes(idKey)) hits.push({ key: idKey, where: "header" });
      else if (hVal.includes(idKey + "="))
        hits.push({ key: idKey, where: "header" });
    }
  }

  // Cookie names (response)
  for (const name of cookieNamesFromResponse ?? []) {
    const n = name.toLowerCase();
    if (IDENTIFIER_KEYS.includes(n)) hits.push({ key: n, where: "cookieName" });
    if (n.startsWith("_ga_")) hits.push({ key: "_ga", where: "cookieName" });
  }

  // POST body scan (don’t store values; just detect keys)
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

  // De-dupe
  const uniq = new Map<string, IdentifierHit>();
  for (const h of hits) uniq.set(`${h.key}:${h.where}`, h);
  return [...uniq.values()];
}

// ---- Behavior-based tracking heuristics (no fixed subdomain list required)
// Common urls for event collection endpoints
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

// ---- Scoring helpers (Stape-style)
function clamp(n: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, n));
}

function ratio(n: number, d: number) {
  return d > 0 ? n / d : 0;
}

// Smooth saturating curve for count signals.
function saturatingScore(x: number, k = 3) {
  return clamp((1 - Math.exp(-x / k)) * 100);
}

export async function runAudit(targetUrl: string) {
  const browser: Browser = await chromium.launch({
    headless: true,
    args: ["--no-sandbox"],
  });

  try {
    const context = await browser.newContext();
    const page = await context.newPage();

    // First vs third-party classification
    const baseDomain = getRegistrableDomain(targetUrl);

    // ---- Request/endpoint mapping storage
    const requestRecords: RequestRecord[] = [];
    const hosts = new Map<string, HostStats>();
    const reqToIndex = new Map<Request, number>();

    // ---- Cookie storage
    const allServerCookies: Array<{
      cookie: string; // "name=value"
      domain: string; // parsed Domain= attr or fallback host
      setBy: string; // response hostname
      source: "server-set";
    }> = [];
    const browserCookies: any[] = [];

    // ---- Platform patterns (cookie-based)
    const PLATFORM_PATTERNS: Record<string, RegExp[]> = {
      Facebook: [/facebook\.com/, /fbp/, /fbc/],
      Google: [/google\.com/, /gcl_/, /_ga/, /_gid/],
      TikTok: [/tiktok\.com/, /tt_/, /_ttp/],
      Klaviyo: [/klaviyo\.com/, /_kla_id/],
      Pinterest: [/pinterest\.com/, /_pin_/, /_pinterest/],
      Snap: [/snapchat\.com/, /sc_/, /_scid/],
      Other: [],
    };

    // ---- Request listener: collect URLs, methods, identifiers, and host stats
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

    // ---- Response listener: capture status and server-set cookies
    page.on("response", async (resp: Response) => {
      try {
        const url = new URL(resp.url());
        const hostname = normalizeHostname(url.hostname);
        const group = classifyHost(hostname, baseDomain);

        const headers = await resp.allHeaders();
        const req = resp.request();

        // enrich request record
        const idx = reqToIndex.get(req);
        const record = idx !== undefined ? requestRecords[idx] : undefined;
        if (record) {
          record.status = resp.status();
          record.ok = resp.ok();
        }

        // Set-Cookie
        const setCookieHeader =
          (headers as any)["set-cookie"] ?? (headers as any)["Set-Cookie"];

        if (setCookieHeader) {
          const rawCookieLines = Array.isArray(setCookieHeader)
            ? setCookieHeader.flatMap((v: string) => splitSetCookie(v))
            : splitSetCookie(setCookieHeader);

          const cookieNamesForThisResponse: string[] = [];

          rawCookieLines.forEach((line) => {
            const name = extractCookieName(line);
            if (name) cookieNamesForThisResponse.push(name);

            const cookieDomain = extractCookieDomainFromSetCookie(
              line,
              hostname,
            );

            allServerCookies.push({
              cookie: (line.split(";")[0] ?? "").trim(), // "name=value"
              domain: cookieDomain,
              setBy: hostname,
              source: "server-set",
            });
          });

          // update host stats
          const stat = getOrInitHostStats(hosts, hostname, group);
          stat.setCookieResponses += 1;
          stat.setCookieCount += cookieNamesForThisResponse.length;
          for (const n of cookieNamesForThisResponse) bump(stat.cookieNames, n);

          // update request record
          if (record) {
            record.setCookieNames = cookieNamesForThisResponse;
            record.setCookieCount = cookieNamesForThisResponse.length;

            // identifier scan using cookie names too
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

            // rebuild per-host identifier counts (MVP safe)
            stat.identifierHits = 0;
            stat.identifierKeys = {};
            for (const r of requestRecords) {
              if (normalizeHostname(r.hostname) !== stat.hostname) continue;
              for (const hit of r.identifierHits ?? []) {
                stat.identifierHits += 1;
                bump(stat.identifierKeys, hit.key);
              }
            }
          }
        }
      } catch {
        /* ignore */
      }
    });

    // ---- Load page
    const start = Date.now();
    try {
      await page.goto(targetUrl, {
        waitUntil: "domcontentloaded",
        timeout: 45000,
      });
      await page
        .waitForLoadState("networkidle", { timeout: 15000 })
        .catch(() => {});
    } catch (err) {
      console.warn(
        `⚠️ Navigation warning for ${targetUrl}:`,
        (err as Error).message,
      );
    }
    const loadTimeMS = Date.now() - start;

    // ---- Light interaction to trigger more tags (optional but helpful)
    try {
      await page.waitForTimeout(2000);
      await page.mouse.wheel(0, 1200);
      await page.waitForTimeout(2000);
    } catch {
      /* ignore */
    }

    // ---- Collect browser cookies
    const cookies = await context.cookies();
    cookies.forEach((c) => browserCookies.push(c));

    // ---- Correlate browser cookies to server-set cookies (STRONGER matching)
    browserCookies.forEach((c) => {
      const match = allServerCookies.find((s) => {
        const serverName = s.cookie.split("=")[0];
        if (c.name !== serverName) return false;

        const cd = normalizeHostname(String(c.domain ?? "")).replace(/^\./, "");
        const sd = normalizeHostname(String(s.domain ?? "")).replace(/^\./, "");

        // cookie domain must be equal or a parent/child relationship
        return cd === sd || cd.endsWith("." + sd) || sd.endsWith("." + cd);
      });

      if (match) {
        c.setByServer = match.setBy; // response hostname that set it
        c.setCookieDomain = match.domain; // parsed Domain= attr (or fallback)
      }
    });

    // ---- Platform classification (cookie name/domain)
    function detectPlatform(cookieName: string, cookieDomain: string): string {
      for (const [platform, patterns] of Object.entries(PLATFORM_PATTERNS)) {
        if (patterns.some((re) => re.test(cookieName) || re.test(cookieDomain)))
          return platform;
      }
      return "Other";
    }
    browserCookies.forEach(
      (c) => (c.platform = detectPlatform(c.name, c.domain)),
    );

    // ---- Build endpoint grouping
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

    // ---- Behavior-based “first-party routed tracking endpoint” detection
    const trackingFirstPartySubdomains = Object.values(
      endpoints.subdomains,
    ).filter((s) => hostLooksLikeTracking(s));
    const trackingRoot = Object.values(endpoints.root).filter((s) =>
      hostLooksLikeTracking(s),
    );

    const trackingHosts = new Set<string>([
      ...trackingFirstPartySubdomains.map((h) => h.hostname),
      ...trackingRoot.map((h) => h.hostname),
    ]);

    // ✅ first-party tracking subdomain hostnames ONLY
    const trackingFirstPartySubdomainHosts = new Set<string>(
      trackingFirstPartySubdomains.map((h) => normalizeHostname(h.hostname)),
    );

    // ---- Beacon breakdown (NOTE: these are *browser* requests; treat as “first-party routed” vs “third-party”)
    let computedFirstPartyRouted = 0;
    let computedThirdParty = 0;

    for (const r of requestRecords) {
      if (r.group === "thirdParty") {
        computedThirdParty++;
        continue;
      }
      if (trackingHosts.has(r.hostname)) computedFirstPartyRouted++;
    }

    // ---- Cookie metrics
    const firstPartyCookies = browserCookies.filter((c) =>
      normalizeHostname(c.domain).endsWith(baseDomain),
    );

    const thirdPartyCookies = browserCookies.filter(
      (c) => !normalizeHostname(c.domain).endsWith(baseDomain),
    );

    const insecureCookies = browserCookies.filter(
      (c) => c.sameSite === "None" || !c.secure,
    );

    const serverSetCookies = browserCookies.filter((c) => c.setByServer);

    // ✅ First-party tracking subdomain cookies (server-set correlation)
    const firstPartyTrackingSubdomainCookies = browserCookies.filter((c) => {
      const setBy = normalizeHostname(c.setByServer ?? "");
      if (!setBy) return false;
      if (!trackingFirstPartySubdomainHosts.has(setBy)) return false;
      return normalizeHostname(c.domain).endsWith(baseDomain);
    });

    // "First-party server cookies" = cookies set by any first-party host (root OR any subdomain)
    const firstPartyHostnames = new Set<string>([
      ...Object.keys(endpoints.root),
      ...Object.keys(endpoints.subdomains),
    ]);

    const firstPartyServerCookies = browserCookies.filter((c) => {
      const setBy = normalizeHostname(c.setByServer ?? "");
      return setBy.length > 0 && firstPartyHostnames.has(setBy);
    });

    // ---- Cookies by platform (detailed)
    const cookiesByPlatformDetailed: Record<string, PlatformCookieStats> = {};

    function classifySetterGroup(
      setByHost: string | undefined | null,
    ): SetterGroup {
      const h = normalizeHostname(setByHost ?? "");
      if (!h) return "unknown";
      return classifyHost(h, baseDomain);
    }

    function initPlatformStats(): PlatformCookieStats {
      return {
        total: 0,
        scope: { firstParty: 0, thirdParty: 0 },
        setMethod: { server: 0, client: 0 },
        serverSetterGroup: {
          root: 0,
          subdomain: 0,
          thirdParty: 0,
          unknown: 0,
        },
        firstPartyServerSet: 0,
        firstPartyTrackingSubdomainServerSet: 0,
        insecure: 0,
        uniqueCookieNames: 0,
        topCookieNames: [],
        domains: { firstParty: [], thirdParty: [] },
        serverSetByHosts: { root: [], subdomain: [], thirdParty: [] },
      };
    }

    const platformNameCounts: Record<string, Record<string, number>> = {};

    for (const c of browserCookies) {
      const platform = c.platform || "Other";
      if (!cookiesByPlatformDetailed[platform]) {
        cookiesByPlatformDetailed[platform] = initPlatformStats();
        platformNameCounts[platform] = {};
      }

      const stats = cookiesByPlatformDetailed[platform];
      stats.total += 1;

      // Scope party (cookie.domain)
      const scopeParty: CookieParty = isFirstPartyCookieDomain(
        c.domain,
        baseDomain,
      )
        ? "firstParty"
        : "thirdParty";

      stats.scope[scopeParty] += 1;
      if (scopeParty === "firstParty")
        uniqPush(stats.domains.firstParty, normalizeHostname(c.domain));
      else uniqPush(stats.domains.thirdParty, normalizeHostname(c.domain));

      // Insecure
      const insecure = c.sameSite === "None" || !c.secure;
      if (insecure) stats.insecure += 1;

      // Set method + setter host grouping
      const isServer = Boolean(c.setByServer);
      if (isServer) {
        stats.setMethod.server += 1;

        const setterGroup = classifySetterGroup(c.setByServer);
        stats.serverSetterGroup[setterGroup] += 1;

        const sb = normalizeHostname(c.setByServer);
        if (setterGroup === "root") uniqPush(stats.serverSetByHosts.root, sb);
        else if (setterGroup === "subdomain")
          uniqPush(stats.serverSetByHosts.subdomain, sb);
        else if (setterGroup === "thirdParty")
          uniqPush(stats.serverSetByHosts.thirdParty, sb);

        if (setterGroup === "root" || setterGroup === "subdomain") {
          stats.firstPartyServerSet += 1;
        }

        if (trackingFirstPartySubdomainHosts.has(sb)) {
          stats.firstPartyTrackingSubdomainServerSet += 1;
        }
      } else {
        stats.setMethod.client += 1;
      }

      // Top cookie name counts
      const nameKey = String(c.name ?? "");
      platformNameCounts[platform][nameKey] =
        (platformNameCounts[platform][nameKey] ?? 0) + 1;
    }

    for (const [platform, stats] of Object.entries(cookiesByPlatformDetailed)) {
      const nameMap = platformNameCounts[platform] ?? {};
      stats.uniqueCookieNames = Object.keys(nameMap).length;
      stats.topCookieNames = topN(nameMap, 6);
    }

    // compact shape (backwards compatible)
    const cookiesByPlatform: Record<
      string,
      { firstParty: number; thirdParty: number }
    > = {};
    for (const [platform, stats] of Object.entries(cookiesByPlatformDetailed)) {
      cookiesByPlatform[platform] = {
        firstParty: stats.scope.firstParty,
        thirdParty: stats.scope.thirdParty,
      };
    }

    // -------------------------
    // Stape-style scoring signals
    // -------------------------
    const totalRequests = requestRecords.length || 1;

    const firstPartyRequests = requestRecords.filter(
      (r) => r.group !== "thirdParty",
    );
    const thirdPartyRequests = requestRecords.filter(
      (r) => r.group === "thirdParty",
    );

    const firstPartyPOSTs = firstPartyRequests.filter(
      (r) => r.method === "POST",
    );

    const firstPartyCollectorHosts = new Set<string>([
      ...trackingRoot.map((h) => normalizeHostname(h.hostname)),
      ...trackingFirstPartySubdomains.map((h) => normalizeHostname(h.hostname)),
    ]);

    const firstPartyCollectorPOSTs = firstPartyPOSTs.filter((r) =>
      firstPartyCollectorHosts.has(normalizeHostname(r.hostname)),
    );

    const fpCollectorIdHits = firstPartyCollectorPOSTs.reduce((acc, r) => {
      return acc + (r.identifierHits?.length ?? 0);
    }, 0);

    const fpCollectorIdKeys = new Set<string>();
    for (const r of firstPartyCollectorPOSTs) {
      for (const hit of r.identifierHits ?? []) fpCollectorIdKeys.add(hit.key);
    }
    const fpCollectorIdKeyCount = fpCollectorIdKeys.size;

    const thirdPartyShare = ratio(thirdPartyRequests.length, totalRequests);

    const insecureRatio =
      browserCookies.length > 0
        ? insecureCookies.length / browserCookies.length
        : 1;

    const fpServerSetCookies = firstPartyServerCookies.length;
    const fpTrackingServerSetCookies =
      firstPartyTrackingSubdomainCookies.length;

    // ---- Scoring (closer to Stape feel)
    let routingStrength = 0;
    routingStrength +=
      0.75 * saturatingScore(firstPartyCollectorPOSTs.length, 2.5);
    routingStrength += firstPartyCollectorHosts.size > 0 ? 15 : 0;
    routingStrength = clamp(routingStrength);

    let identifierContinuity = 0;
    identifierContinuity += 0.75 * saturatingScore(fpCollectorIdKeyCount, 2);
    identifierContinuity += 0.25 * saturatingScore(fpCollectorIdHits, 6);
    identifierContinuity = clamp(identifierContinuity);

    let cookieQuality = 0;
    cookieQuality += 0.55 * saturatingScore(fpServerSetCookies, 3);
    cookieQuality += 0.35 * saturatingScore(fpTrackingServerSetCookies, 2);
    cookieQuality += 0.1 * clamp((1 - insecureRatio) * 100);
    cookieQuality = clamp(cookieQuality);

    const thirdPartyReliance = clamp(thirdPartyShare * 100);

    let overall =
      0.4 * routingStrength +
      0.25 * identifierContinuity +
      0.2 * cookieQuality +
      0.15 * (100 - thirdPartyReliance);

    overall = clamp(overall);
    const overallScore = Math.round(overall);

    let technical =
      0.5 * cookieQuality +
      0.35 * routingStrength +
      0.15 * clamp((1 - insecureRatio) * 100);

    technical = clamp(technical);

    let firstPartyBias =
      0.55 * routingStrength +
      0.3 * saturatingScore(fpTrackingServerSetCookies, 2) +
      0.15 * saturatingScore(fpServerSetCookies, 3);

    firstPartyBias = clamp(firstPartyBias);

    let potentialWithFirstParty = clamp(100 - overall, 0, 100);
    if (routingStrength > 70) potentialWithFirstParty -= 10;
    if (routingStrength > 85) potentialWithFirstParty -= 10;
    potentialWithFirstParty = clamp(potentialWithFirstParty, 35, 95);

    const scores = {
      technical: Math.round(technical),
      firstPartyBias: Math.round(firstPartyBias),
      potentialWithFirstParty: Math.round(potentialWithFirstParty),
    };

    // A small “health” metric you had before (kept, but now just a driver)
    const cookieHealthScore =
      (firstPartyTrackingSubdomainCookies.length /
        (browserCookies.length || 1)) *
      100;

    // ---- Output
    const result = {
      summary: {
        url: targetUrl,
        title: await page.title().catch(() => ""),
        timestamp: new Date().toISOString(),
        baseDomain,
      },
      performance: {
        loadTimeMS,
        transferSizeKB: Math.round((await page.content()).length / 1024),
      },
      tracking: {
        // These are browser requests. Treat “server” as “first-party routed” for UI wording.
        beaconBreakdown: {
          firstPartyRouted: computedFirstPartyRouted,
          thirdParty: computedThirdParty,
          total: requestRecords.length,
        },
        // Optional debug:
        // trackingHosts: Array.from(trackingHosts),
        // trackingFirstPartySubdomainHosts: Array.from(trackingFirstPartySubdomainHosts),
      },
      cookies: {
        total: browserCookies.length,
        firstParty: firstPartyCookies.length,
        thirdParty: thirdPartyCookies.length,
        insecure: insecureCookies.length,
        serverSet: serverSetCookies.length,

        // broad “server-set by any first-party host”
        firstPartyServerSet: firstPartyServerCookies.length,

        // ✅ key signal
        firstPartyTrackingSubdomainServerSet:
          firstPartyTrackingSubdomainCookies.length,

        // old compact summary (kept)
        byPlatform: cookiesByPlatform,

        // richer breakdown
        byPlatformDetailed: cookiesByPlatformDetailed,
      },
      // endpoints,
      scores,
      scoreDrivers: {
        overallScore,
        routingStrength,
        identifierContinuity,
        cookieQuality,
        thirdPartyReliance,

        firstPartyCollectorHostsCount: firstPartyCollectorHosts.size,
        firstPartyCollectorPOSTs: firstPartyCollectorPOSTs.length,
        fpCollectorIdKeyCount,
        fpCollectorIdHits,

        fpServerSetCookies,
        fpTrackingServerSetCookies,

        hasFirstPartyCookies: firstPartyCookies.length > 0,
        hasTrackingSubdomainServerSetCookies:
          firstPartyTrackingSubdomainCookies.length > 0,

        insecureCookieRatio: insecureRatio,
        thirdPartyShare,
        cookieHealthScore,
      },
      insights: {
        diagnosis:
          routingStrength >= 60
            ? "First-party routed collection detected"
            : "Mostly client-side / third-party collection",
        opportunity:
          routingStrength >= 70
            ? "Strong foundation; minor improvements possible"
            : "Significant opportunity to implement first-party routing + cookie hardening",
        notes: `${insecureCookies.length} cookies lack Secure or SameSite flags.`,
      },
    };

    return result;
  } finally {
    await browser.close().catch(() => {});
  }
}
