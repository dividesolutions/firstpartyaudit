// src/audit.ts
import { chromium } from "playwright";

export async function runAudit(targetUrl: string) {
  const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  const context = await browser.newContext();
  const page = await context.newPage();

  const base = new URL(targetUrl);
  const baseDomain = base.hostname.split(".").slice(-2).join(".");

  // --- tracking counters
  let totalBeacons = 0;
  let clientSideEvents = 0;
  let serverSideEvents = 0;
  const detectedServerDomains = new Set<string>();

  // --- cookie storage
  const allServerCookies: any[] = [];
  const browserCookies: any[] = [];

  // --- detection patterns
  const serverSideKeywords = ["track", "data", "events", "analytics", "measure", "collect", "t", "cookies", "pixel", "ss"];
  const excludedPaths = ["/cdn/", "/shop/", "/assets/", "/theme", "observer.js", "bundle.js"];

  const PLATFORM_PATTERNS: Record<string, RegExp[]> = {
    Facebook: [/facebook\.com/, /fbp/, /fbc/],
    Google: [/google\.com/, /gcl_/, /_ga/, /_gid/],
    TikTok: [/tiktok\.com/, /tt_/, /_ttp/],
    Klaviyo: [/klaviyo\.com/, /_kla_id/],
    Pinterest: [/pinterest\.com/, /_pin_/, /_pinterest/],
    Snap: [/snapchat\.com/, /sc_/, /_scid/],
    Other: [],
  };

  // --- network listener
  page.on("response", async (resp) => {
    try {
      const url = new URL(resp.url());
      const headers = await resp.allHeaders();

      // --- capture server-set cookies
      if (headers["set-cookie"]) {
        const cookieList = headers["set-cookie"].split(",");
        cookieList.forEach((c) => {
          const cookieDomain = url.hostname.toLowerCase();
          const isFirstParty = cookieDomain.endsWith(baseDomain);
          const fromServerSubdomain = /^(data|track|events|analytics)\./.test(cookieDomain);
          allServerCookies.push({
            cookie: c.split(";")[0].trim(),
            domain: cookieDomain,
            isFirstParty,
            fromServerSubdomain,
            source: "server-set",
          });
        });
      }

      // --- classify requests
      const hostname = url.hostname.toLowerCase();
      const pathname = url.pathname.toLowerCase();
      totalBeacons++;

      const isFirstPartyServer =
        serverSideKeywords.some(
          (k) => hostname.startsWith(k + ".") || pathname.includes("/" + k)
        ) &&
        !excludedPaths.some((x) => pathname.includes(x) || hostname.includes("cdn"));

      if (isFirstPartyServer) {
        serverSideEvents++;
        detectedServerDomains.add(resp.url());
      } else if (hostname.endsWith(baseDomain)) {
        clientSideEvents++;
      }
    } catch {
      /* ignore parsing issues */
    }
  });

  // --- load page
  const start = Date.now();
  await page.goto(targetUrl, { waitUntil: "networkidle", timeout: 60000 });
  const loadTimeMS = Date.now() - start;

  // --- collect cookies visible to browser
  const cookies = await context.cookies();
  cookies.forEach((c) => browserCookies.push(c));

  // --- correlate with server-set cookies
  browserCookies.forEach((c) => {
    const match = allServerCookies.find((s) => c.name === s.cookie.split("=")[0]);
    c.setByServer = match ? match.domain : null;
    c.isFirstPartyServerCookie = match ? match.fromServerSubdomain : false;
  });

  // --- detect ad / analytics platform for each cookie
  function detectPlatform(cookieName: string, cookieDomain: string): string {
    for (const [platform, patterns] of Object.entries(PLATFORM_PATTERNS)) {
      if (patterns.some((re) => re.test(cookieName) || re.test(cookieDomain))) return platform;
    }
    return "Other";
  }

  browserCookies.forEach((c) => {
    c.platform = detectPlatform(c.name, c.domain);
  });

  // --- cookie metrics
  const firstPartyCookies = browserCookies.filter((c) => c.domain.includes(baseDomain));
  const thirdPartyCookies = browserCookies.filter((c) => !c.domain.includes(baseDomain));
  const insecureCookies = browserCookies.filter(
    (c) => c.sameSite === "None" || !c.secure
  );
  const serverSetCookies = browserCookies.filter((c) => c.setByServer);
  const firstPartyServerCookies = browserCookies.filter((c) => c.isFirstPartyServerCookie);

  // --- cookies by platform
  const cookiesByPlatform: Record<string, { firstParty: number; thirdParty: number }> = {};
  browserCookies.forEach((c) => {
    const platform = c.platform || "Other";
    const isFirst = c.domain.includes(baseDomain);
    if (!cookiesByPlatform[platform]) cookiesByPlatform[platform] = { firstParty: 0, thirdParty: 0 };
    if (isFirst) cookiesByPlatform[platform].firstParty++;
    else cookiesByPlatform[platform].thirdParty++;
  });

  // --- scoring
  const cookieHealthScore =
    (firstPartyServerCookies.length / (browserCookies.length || 1)) * 100;

  const scores = {
    technical: Math.min(100, 50 + cookieHealthScore / 2),
    firstPartyBias: Math.min(100, 70 + firstPartyServerCookies.length),
    potentialWithFirstParty: 95,
  };

  // --- output JSON
  const result = {
    summary: {
      url: targetUrl,
      title: await page.title(),
      timestamp: new Date().toISOString(),
    },
    performance: {
      loadTimeMS,
      transferSizeKB: Math.round((await page.content()).length / 1024),
    },
    tracking: {
      beaconBreakdown: { client: clientSideEvents, server: serverSideEvents, total: totalBeacons },
      serverDomainsDetected: Array.from(detectedServerDomains),
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
    scores,
    insights: {
      diagnosis:
        serverSideEvents > 0
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
}
