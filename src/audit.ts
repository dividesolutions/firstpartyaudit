// src/audit.ts
import { chromium } from "playwright";

export async function runAudit(targetUrl: string) {
  const browser = await chromium.launch({
    headless: true,
    args: ["--no-sandbox"],
  });
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

  // --- True first-party server subdomain patterns (already includes ss, etc.)
  const firstPartyPatterns = (
    process.env.FIRST_PARTY_PATTERNS ||
    "data,track,events,analytics,measure,stats,metrics,collect,collector,t,ss,sgtm,tagging,gtm"
  )
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

      // Capture server-set cookies (including Domain= attr from Set-Cookie)
      if (headers["set-cookie"]) {
        const rawCookies = headers["set-cookie"]
          .split(/,(?=[^ ;]+=)/) // safer split for multiple cookies
          .map((c) => c.trim());

        rawCookies.forEach((c) => {
          const parts = c.split(";");
          const nameValue = parts.shift()?.trim() || "";
          const domainAttr = parts.find((p) =>
            p.trim().toLowerCase().startsWith("domain=")
          );
          const cookieDomain = domainAttr
            ? domainAttr.split("=")[1].trim().replace(/^\./, "").toLowerCase()
            : url.hostname.toLowerCase();

          const fromServerSubdomain = trueFirstPartyRegex.test(url.hostname);

          allServerCookies.push({
            cookie: nameValue,
            domain: cookieDomain,
            fromServerSubdomain,
            setBy: url.hostname,
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

  // --- Load the page with safer timing ---
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

  // --- Collect cookies visible to the browser
  const cookies = await context.cookies();
  cookies.forEach((c) => browserCookies.push(c));

  // --- Correlate cookies with server-set cookies
  browserCookies.forEach((c) => {
    const match = allServerCookies.find(
      (s) =>
        c.name === s.cookie.split("=")[0] &&
        (c.domain.includes(s.domain) || s.domain.includes(baseDomain))
    );
    if (match) {
      c.setByServer = match.setBy;
      c.isFirstPartyServerCookie =
        match.fromServerSubdomain || trueFirstPartyRegex.test(match.setBy);
    }
  });

  // --- Detect ad / analytics platform
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

  // --- Cookie metrics setup
  const serverDomainsList = Array.from(detectedServerDomains).map((u) =>
    new URL(u).hostname.toLowerCase()
  );

  // Upgrade platform cookies if a first-party tracking subdomain was observed
  if (serverDomainsList.some((d) => trueFirstPartyRegex.test(d))) {
    browserCookies.forEach((c) => {
      if (
        /(_fbp|_fbc|_ga|_gid|_gcl_au|_ttcid|_ttp)/.test(c.name) &&
        c.domain.endsWith(baseDomain)
      ) {
        c.isFirstPartyServerCookie = true;
      }
    });
  }

  // ---- Cookie metrics (redefined)
  const firstPartyServerCookies = browserCookies.filter(
    (c) => c.isFirstPartyServerCookie && c.domain.endsWith(baseDomain)
  );

  const firstPartyCookies = browserCookies.filter(
    (c) =>
      trueFirstPartyRegex.test(c.domain) ||
      serverDomainsList.some((h) => c.domain.includes(h.split(".")[0]))
  );

  const thirdPartyCookies = browserCookies.filter(
    (c) =>
      !trueFirstPartyRegex.test(c.domain) &&
      !serverDomainsList.some((h) => c.domain.includes(h.split(".")[0]))
  );

  const insecureCookies = browserCookies.filter(
    (c) => c.sameSite === "None" || !c.secure
  );
  const serverSetCookies = browserCookies.filter((c) => c.setByServer);

  // ---- Cookies by platform (using new first-party logic)
  const cookiesByPlatform: Record<
    string,
    { firstParty: number; thirdParty: number }
  > = {};
  browserCookies.forEach((c) => {
    const platform = c.platform || "Other";
    const isTrueFirstParty =
      c.isFirstPartyServerCookie ||
      trueFirstPartyRegex.test(c.domain) ||
      serverDomainsList.some((h) => c.domain.includes(h.split(".")[0]));
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
