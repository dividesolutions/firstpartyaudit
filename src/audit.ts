// src/audit.ts
import { chromium } from "playwright";

export async function runAudit(targetUrl: string) {
  const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  const context = await browser.newContext();
  const page = await context.newPage();

  const base = new URL(targetUrl);
  const baseDomain = base.hostname.split(".").slice(-2).join(".");

  // Counters
  let totalBeacons = 0;
  let clientSideEvents = 0;
  let serverSideEvents = 0;
  const detectedServerDomains = new Set<string>();

  // Storage
  const allServerCookies: any[] = [];
  const browserCookies: any[] = [];

  // --- Platform patterns
  const PLATFORM_PATTERNS: Record<string, RegExp[]> = {
    Facebook: [/facebook\.com/, /fbp/, /fbc/],
    Google: [/google\.com/, /gcl_/, /_ga/, /_gid/],
    TikTok: [/tiktok\.com/, /tt_/, /_ttp/],
    Klaviyo: [/klaviyo\.com/, /_kla_id/],
    Pinterest: [/pinterest\.com/, /_pin_/, /_pinterest/],
    Snap: [/snapchat\.com/, /sc_/, /_scid/],
    Other: [],
  };

  // --- True first-party server subdomain patterns
  const firstPartyPatterns = (process.env.FIRST_PARTY_PATTERNS ||
    "data,track,events,analytics,measure")
    .split(",")
    .map((s) => s.trim().toLowerCase());

  const trueFirstPartyRegex = new RegExp(
    `^(${firstPartyPatterns.join("|")})\\.${baseDomain.replace(".", "\\.")}$`
  );

  // --- Network listener
  page.on("response", async (resp) => {
    try {
      const url = new URL(resp.url());
      const headers = await resp.allHeaders();
      const hostname = url.hostname.toLowerCase();
      totalBeacons++;

      // Capture server-set cookies
      if (headers["set-cookie"]) {
        const cookieList = headers["set-cookie"].split(",");
        cookieList.forEach((c) => {
          const cookieDomain = hostname;
          const fromServerSubdomain = trueFirstPartyRegex.test(cookieDomain);
          allServerCookies.push({
            cookie: c.split(";")[0].trim(),
            domain: cookieDomain,
            fromServerSubdomain,
            source: "server-set",
          });
        });
      }

      // Classify request
      const isBrandOwnedSubdomain = trueFirstPartyRegex.test(hostname);
      const isClearlyThirdParty =
        !hostname.endsWith(baseDomain) || hostname === baseDomain;

      if (isBrandOwnedSubdomain) {
        serverSideEvents++;
        detectedServerDomains.add(resp.url());
      } else {
        clientSideEvents++;
      }
    } catch {
      /* ignore */
    }
  });

  // --- Load the page
  const start = Date.now();
  await page.goto(targetUrl, { waitUntil: "networkidle", timeout: 60000 });
  const loadTimeMS = Date.now() - start;

  // --- Collect cookies visible to the browser
  const cookies = await context.cookies();
  cookies.forEach((c) => browserCookies.push(c));

  // --- Correlate cookies with server-set cookies
  browserCookies.forEach((c) => {
    const match = allServerCookies.find((s) => c.name === s.cookie.split("=")[0]);
    c.setByServer = match ? match.domain : null;
    c.isFirstPartyServerCookie = match ? match.fromServerSubdomain : false;
  });

  // --- Detect ad / analytics platform
  function detectPlatform(cookieName: string, cookieDomain: string): string {
    for (const [platform, patterns] of Object.entries(PLATFORM_PATTERNS)) {
      if (patterns.some((re) => re.test(cookieName) || re.test(cookieDomain))) return platform;
    }
    return "Other";
  }
  browserCookies.forEach((c) => (c.platform = detectPlatform(c.name, c.domain)));

  // ---- Cookie metrics (redefined)
  const firstPartyServerCookies = browserCookies.filter(
    (c) => c.isFirstPartyServerCookie && trueFirstPartyRegex.test(c.domain)
  );

  const firstPartyCookies = browserCookies.filter((c) =>
    trueFirstPartyRegex.test(c.domain)
  );

  const thirdPartyCookies = browserCookies.filter(
    (c) => !trueFirstPartyRegex.test(c.domain)
  );

  const insecureCookies = browserCookies.filter(
    (c) => c.sameSite === "None" || !c.secure
  );
  const serverSetCookies = browserCookies.filter((c) => c.setByServer);

  // ---- Cookies by platform (using new first-party logic)
  const cookiesByPlatform: Record<string, { firstParty: number; thirdParty: number }> = {};
  browserCookies.forEach((c) => {
    const platform = c.platform || "Other";
    const isTrueFirstParty = trueFirstPartyRegex.test(c.domain);
    if (!cookiesByPlatform[platform])
      cookiesByPlatform[platform] = { firstParty: 0, thirdParty: 0 };
    if (isTrueFirstParty) cookiesByPlatform[platform].firstParty++;
    else cookiesByPlatform[platform].thirdParty++;
  });

  // ---- Scoring
  const cookieHealthScore =
    (firstPartyServerCookies.length / (browserCookies.length || 1)) * 100;
  const scores = {
    technical: Math.min(100, 50 + cookieHealthScore / 2),
    firstPartyBias: Math.min(100, 70 + firstPartyServerCookies.length),
    potentialWithFirstParty: 95,
  };

  // ---- JSON output
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
      beaconBreakdown: {
        client: clientSideEvents,
        server: serverSideEvents,
        total: totalBeacons,
      },
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
