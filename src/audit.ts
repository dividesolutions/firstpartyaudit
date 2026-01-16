// // src/audit.ts
// import { chromium } from "playwright";

// export async function runAudit(targetUrl: string) {
//   const browser = await chromium.launch({
//     headless: true,
//     args: ["--no-sandbox"],
//   });

//   try {
//     const context = await browser.newContext();
//     const page = await context.newPage();

//     const base = new URL(targetUrl);
//     const baseDomain = base.hostname.split(".").slice(-2).join(".");

//     // Counters
//     let totalBeacons = 0;
//     let clientSideEvents = 0;
//     let serverSideEvents = 0;
//     const detectedServerDomains = new Set<string>();

//     // Storage
//     const allServerCookies: any[] = [];
//     const browserCookies: any[] = [];

//     // --- Platform patterns
//     const PLATFORM_PATTERNS: Record<string, RegExp[]> = {
//       Facebook: [/facebook\.com/, /fbp/, /fbc/],
//       Google: [/google\.com/, /gcl_/, /_ga/, /_gid/],
//       TikTok: [/tiktok\.com/, /tt_/, /_ttp/],
//       Klaviyo: [/klaviyo\.com/, /_kla_id/],
//       Pinterest: [/pinterest\.com/, /_pin_/, /_pinterest/],
//       Snap: [/snapchat\.com/, /sc_/, /_scid/],
//       Other: [],
//     };

//     // --- True first-party server subdomain patterns (already includes ss, etc.)
//     const firstPartyPatterns = (
//       process.env.FIRST_PARTY_PATTERNS ||
//       "data,track,events,analytics,measure,stats,metrics,collect,collector,t,ss,sgtm,tagging,gtm"
//     )
//       .split(",")
//       .map((s) => s.trim().toLowerCase());

//     const trueFirstPartyRegex = new RegExp(
//       `^(${firstPartyPatterns.join("|")})\\.${baseDomain.replace(".", "\\.")}$`
//     );

//     // --- Network listener
//     page.on("response", async (resp) => {
//       try {
//         const url = new URL(resp.url());
//         const headers = await resp.allHeaders();
//         const hostname = url.hostname.toLowerCase();
//         totalBeacons++;

//         // Capture server-set cookies (including Domain= attr from Set-Cookie)
//         if (headers["set-cookie"]) {
//           const rawCookies = headers["set-cookie"]
//             .split(/,(?=[^ ;]+=)/) // safer split for multiple cookies
//             .map((c) => c.trim());

//           rawCookies.forEach((c) => {
//             const parts = c.split(";");
//             const nameValue = parts.shift()?.trim() || "";
//             const domainAttr = parts.find((p) =>
//               p.trim().toLowerCase().startsWith("domain=")
//             );
//             const cookieDomain = domainAttr
//               ? domainAttr.split("=")[1].trim().replace(/^\./, "").toLowerCase()
//               : url.hostname.toLowerCase();

//             const fromServerSubdomain = trueFirstPartyRegex.test(url.hostname);

//             allServerCookies.push({
//               cookie: nameValue,
//               domain: cookieDomain,
//               fromServerSubdomain,
//               setBy: url.hostname,
//               source: "server-set",
//             });
//           });
//         }

//         // Classify request
//         const isBrandOwnedSubdomain = trueFirstPartyRegex.test(hostname);
//         const isClearlyThirdParty =
//           !hostname.endsWith(baseDomain) || hostname === baseDomain;

//         if (isBrandOwnedSubdomain) {
//           serverSideEvents++;
//           detectedServerDomains.add(resp.url());
//         } else {
//           clientSideEvents++;
//         }
//       } catch {
//         /* ignore */
//       }
//     });

//     // --- Load the page with safer timing ---
//     const start = Date.now();
//     try {
//       await page.goto(targetUrl, {
//         waitUntil: "domcontentloaded",
//         timeout: 45000,
//       });
//       await page
//         .waitForLoadState("networkidle", { timeout: 15000 })
//         .catch(() => {});
//     } catch (err) {
//       console.warn(
//         `⚠️ Navigation warning for ${targetUrl}:`,
//         (err as Error).message
//       );
//     }
//     const loadTimeMS = Date.now() - start;

//     // --- Collect cookies visible to the browser
//     const cookies = await context.cookies();
//     cookies.forEach((c) => browserCookies.push(c));

//     // --- Correlate cookies with server-set cookies
//     browserCookies.forEach((c) => {
//       const match = allServerCookies.find(
//         (s) =>
//           c.name === s.cookie.split("=")[0] &&
//           (c.domain.includes(s.domain) || s.domain.includes(baseDomain))
//       );
//       if (match) {
//         c.setByServer = match.setBy;
//         c.isFirstPartyServerCookie =
//           match.fromServerSubdomain || trueFirstPartyRegex.test(match.setBy);
//       }
//     });

//     // --- Detect ad / analytics platform
//     function detectPlatform(cookieName: string, cookieDomain: string): string {
//       for (const [platform, patterns] of Object.entries(PLATFORM_PATTERNS)) {
//         if (patterns.some((re) => re.test(cookieName) || re.test(cookieDomain)))
//           return platform;
//       }
//       return "Other";
//     }
//     browserCookies.forEach(
//       (c) => (c.platform = detectPlatform(c.name, c.domain))
//     );

//     // --- Cookie metrics setup
//     const serverDomainsList = Array.from(detectedServerDomains).map((u) =>
//       new URL(u).hostname.toLowerCase()
//     );

//     // Upgrade platform cookies if a first-party tracking subdomain was observed
//     if (serverDomainsList.some((d) => trueFirstPartyRegex.test(d))) {
//       browserCookies.forEach((c) => {
//         if (
//           /(_fbp|_fbc|_ga|_gid|_gcl_au|_ttcid|_ttp)/.test(c.name) &&
//           c.domain.endsWith(baseDomain)
//         ) {
//           c.isFirstPartyServerCookie = true;
//         }
//       });
//     }

//     // ---- Cookie metrics (redefined)
//     const firstPartyServerCookies = browserCookies.filter(
//       (c) => c.isFirstPartyServerCookie && c.domain.endsWith(baseDomain)
//     );

//     const firstPartyCookies = browserCookies.filter(
//       (c) =>
//         trueFirstPartyRegex.test(c.domain) ||
//         serverDomainsList.some((h) => c.domain.includes(h.split(".")[0]))
//     );

//     const thirdPartyCookies = browserCookies.filter(
//       (c) =>
//         !trueFirstPartyRegex.test(c.domain) &&
//         !serverDomainsList.some((h) => c.domain.includes(h.split(".")[0]))
//     );

//     const insecureCookies = browserCookies.filter(
//       (c) => c.sameSite === "None" || !c.secure
//     );
//     const serverSetCookies = browserCookies.filter((c) => c.setByServer);

//     // ---- Cookies by platform (using new first-party logic)
//     const cookiesByPlatform: Record<
//       string,
//       { firstParty: number; thirdParty: number }
//     > = {};
//     browserCookies.forEach((c) => {
//       const platform = c.platform || "Other";
//       const isTrueFirstParty =
//         c.isFirstPartyServerCookie ||
//         trueFirstPartyRegex.test(c.domain) ||
//         serverDomainsList.some((h) => c.domain.includes(h.split(".")[0]));
//       if (!cookiesByPlatform[platform])
//         cookiesByPlatform[platform] = { firstParty: 0, thirdParty: 0 };
//       if (isTrueFirstParty) cookiesByPlatform[platform].firstParty++;
//       else cookiesByPlatform[platform].thirdParty++;
//     });

//     // ---- Scoring
//     const cookieHealthScore =
//       (firstPartyServerCookies.length / (browserCookies.length || 1)) * 100;
//     const scores = {
//       technical: Math.min(100, 50 + cookieHealthScore / 2),
//       firstPartyBias: Math.min(100, 70 + firstPartyServerCookies.length),
//       potentialWithFirstParty: 95,
//     };

//     // ---- JSON output
//     const result = {
//       summary: {
//         url: targetUrl,
//         title: await page.title(),
//         timestamp: new Date().toISOString(),
//       },
//       performance: {
//         loadTimeMS,
//         transferSizeKB: Math.round((await page.content()).length / 1024),
//       },
//       tracking: {
//         beaconBreakdown: {
//           client: clientSideEvents,
//           server: serverSideEvents,
//           total: totalBeacons,
//         },
//         serverDomainsDetected: Array.from(detectedServerDomains),
//       },
//       cookies: {
//         total: browserCookies.length,
//         firstParty: firstPartyCookies.length,
//         thirdParty: thirdPartyCookies.length,
//         insecure: insecureCookies.length,
//         serverSet: serverSetCookies.length,
//         firstPartyServerSet: firstPartyServerCookies.length,
//         byPlatform: cookiesByPlatform,
//       },
//       scores,
//       insights: {
//         diagnosis:
//           serverSideEvents > 0
//             ? "Server-side tracking detected"
//             : "Client-side only tracking",
//         opportunity:
//           firstPartyServerCookies.length > 0
//             ? "Strong foundation; minor improvements possible"
//             : "Significant opportunity to implement first-party tracking",
//         notes: `${insecureCookies.length} cookies lack Secure or SameSite flags.`,
//       },
//     };

//     await browser.close();
//     return result;
//   } finally {
//     await browser.close().catch(() => {});
//   }
// }
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
  group: HostGroup
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
  fallbackHostname: string
): string {
  const parts = setCookieLine.split(";").map((p) => p.trim());
  const domainAttr = parts.find((p) => p.toLowerCase().startsWith("domain="));
  const cookieDomain = domainAttr
    ? domainAttr.split("=")[1].trim().replace(/^\./, "")
    : fallbackHostname;
  return normalizeHostname(cookieDomain);
}

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
    COLLECTOR_PATH_HINTS.some((hint) => p.toLowerCase().includes(hint))
  );
}

export async function runAudit(targetUrl: string) {
  const browser: Browser = await chromium.launch({
    headless: true,
    args: ["--no-sandbox"],
  });

  try {
    const context = await browser.newContext();
    const page = await context.newPage();

    const baseDomain = getRegistrableDomain(targetUrl);

    // ---- Request/endpoint mapping storage
    const requestRecords: RequestRecord[] = [];
    const hosts = new Map<string, HostStats>();
    const reqToIndex = new Map<Request, number>();

    // ---- Your cookie storage
    const allServerCookies: any[] = [];
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
              hostname
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
        (err as Error).message
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

    // ---- Correlate browser cookies to server-set cookies
    browserCookies.forEach((c) => {
      const match = allServerCookies.find(
        (s) =>
          c.name === s.cookie.split("=")[0] &&
          (c.domain.includes(s.domain) || s.domain.includes(baseDomain))
      );
      if (match) {
        c.setByServer = match.setBy;
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
      (c) => (c.platform = detectPlatform(c.name, c.domain))
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

    // ---- Behavior-based “server-side tracking” detection
    const trackingFirstPartySubdomains = Object.values(
      endpoints.subdomains
    ).filter((s) => hostLooksLikeTracking(s));

    const trackingRoot = Object.values(endpoints.root).filter((s) =>
      hostLooksLikeTracking(s)
    );

    const trackingHosts = new Set<string>([
      ...trackingFirstPartySubdomains.map((h) => h.hostname),
      ...trackingRoot.map((h) => h.hostname),
    ]);

    // ---- Beacon breakdown based on behavior (not name patterns)
    let computedServer = 0;
    let computedClient = 0;
    let computedThirdParty = 0;

    for (const r of requestRecords) {
      const isThirdParty = r.group === "thirdParty";
      if (isThirdParty) computedThirdParty++;

      if (trackingHosts.has(r.hostname)) computedServer++;
      else computedClient++;
    }

    // ---- Cookie metrics (simplified + aligned with endpoint evidence)
    // “First-party server cookies” = cookies that were set by a first-party host (root or subdomain)
    const firstPartyHostnames = new Set<string>([
      ...Object.keys(endpoints.root),
      ...Object.keys(endpoints.subdomains),
    ]);

    const firstPartyServerCookies = browserCookies.filter(
      (c) =>
        c.setByServer &&
        firstPartyHostnames.has(normalizeHostname(c.setByServer))
    );

    // “First-party cookies” = cookie domain ends with baseDomain
    const firstPartyCookies = browserCookies.filter((c) =>
      normalizeHostname(c.domain).endsWith(baseDomain)
    );

    const thirdPartyCookies = browserCookies.filter(
      (c) => !normalizeHostname(c.domain).endsWith(baseDomain)
    );

    const insecureCookies = browserCookies.filter(
      (c) => c.sameSite === "None" || !c.secure
    );

    const serverSetCookies = browserCookies.filter((c) => c.setByServer);

    // ---- Cookies by platform (first-party vs third-party by cookie domain)
    const cookiesByPlatform: Record<
      string,
      { firstParty: number; thirdParty: number }
    > = {};
    browserCookies.forEach((c) => {
      const platform = c.platform || "Other";
      const isFirstParty = normalizeHostname(c.domain).endsWith(baseDomain);
      if (!cookiesByPlatform[platform])
        cookiesByPlatform[platform] = { firstParty: 0, thirdParty: 0 };
      if (isFirstParty) cookiesByPlatform[platform].firstParty++;
      else cookiesByPlatform[platform].thirdParty++;
    });

    // ---- Scoring (keep your approach)
    const cookieHealthScore =
      (firstPartyServerCookies.length / (browserCookies.length || 1)) * 100;

    const scores = {
      technical: Math.min(100, 50 + cookieHealthScore / 2),
      firstPartyBias: Math.min(100, 70 + firstPartyServerCookies.length),
      potentialWithFirstParty: 95,
    };

    const hasFirstPartyServerTracking = trackingHosts.size > 0;

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
        beaconBreakdown: {
          // client/server based on behavior evidence
          client: computedClient,
          server: computedServer,
          thirdParty: computedThirdParty,
          total: requestRecords.length,
        },
        // Only “server domains detected” = first-party tracking-like endpoints
        serverDomainsDetected: Array.from(trackingHosts),
      },
      cookies: {
        total: browserCookies.length,
        firstParty: firstPartyCookies.length,
        thirdParty: thirdPartyCookies.length,
        insecure: insecureCookies.length,
        serverSet: serverSetCookies.length,
        firstPartyServerSet: firstPartyServerCookies.length,
        byPlatform: cookiesByPlatform,
      },
      endpoints,
      scores,
      insights: {
        diagnosis: hasFirstPartyServerTracking
          ? "Server-side tracking detected"
          : "Client-side only tracking",
        opportunity:
          firstPartyServerCookies.length > 0
            ? "Strong foundation; minor improvements possible"
            : "Significant opportunity to implement first-party tracking",
        notes: `${insecureCookies.length} cookies lack Secure or SameSite flags.`,
      },
    };

    await browser.close();
    return result;
  } finally {
    await browser.close().catch(() => {});
  }
}
