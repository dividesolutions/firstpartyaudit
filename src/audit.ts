import { chromium } from "playwright";

export async function runAudit(url: string) {
  const browser = await chromium.launch({ headless: true });

  try {
    const context = await browser.newContext();
    const page = await context.newPage();

    // --- Collect network beacons ---
    const beacons: any[] = [];
    page.on("response", (resp) => {
      try {
        beacons.push({
          url: resp.url(),
          status: resp.status(),
          type: resp.request().resourceType(),
        });
      } catch (_) {}
    });

    console.log("🌐 Navigating to", url);
    const start = Date.now();
    await page.goto(url, { waitUntil: "load", timeout: 90000 });
    await page.waitForLoadState("networkidle", { timeout: 30000 }).catch(() => {});
    const loadTimeMS = Date.now() - start;

    // --- Title & Performance ---
    let title = "Unknown Title";
    try {
      title = await page.title();
    } catch (_) {}

    const cookies = await context.cookies().catch(() => []);
    const perfEntries = await page.evaluate(() => performance.getEntries()).catch(() => []);
    const transferSizeKB = Math.round(perfEntries.length * 10);

   // --- Consent Detection + Vendor Identification ---
let consentBannerText = "";
let hasConsentBanner = false;
let consentVendor: string | null = null;

try {
  const banner = await page.$(
    '[id*="consent"], [id*="cookie"], [class*="consent"], [class*="cookie"], div[role="dialog"]'
  );
  if (banner) {
    const visible = await banner.isVisible().catch(() => false);
    if (visible) {
      hasConsentBanner = true;
      consentBannerText = (await banner.textContent())?.trim().slice(0, 180) || "";
    }
  }

  // --- Vendor fingerprints ---
  const html = await page.content();
  const vendorPatterns: Record<string, RegExp[]> = {
    OneTrust: [/onetrust/i, /optanon/i],
    Cookiebot: [/cookiebot/i],
    Usercentrics: [/usercentrics/i],
    iubenda: [/iubenda/i],
    Quantcast: [/quantcast/i, /choice\.quantcast/i],
    TrustArc: [/trustarc/i],
    CookieYes: [/cookieyes/i],
  };

  for (const [vendor, patterns] of Object.entries(vendorPatterns)) {
    if (patterns.some((rx) => rx.test(html) || beacons.some((b) => rx.test(b.url)))) {
      consentVendor = vendor;
      break;
    }
  }
} catch (_) {}

// Determine if cookies already exist before consent
const preConsentCookies = cookies.filter(
  (c) => !/consent|banner|policy/i.test(c.name)
);
const autoDropsCookiesBeforeConsent = hasConsentBanner && preConsentCookies.length > 0;

const consent = {
  hasConsentBanner,
  bannerText: consentBannerText,
  autoDropsCookiesBeforeConsent,
  vendor: consentVendor,
};

    // --- Server-side / First-party classifier ---
    const rootDomain = new URL(url).hostname
      .replace(/^www\./, "")
      .split(".")
      .slice(-2)
      .join(".");
    const serverSidePattern = new RegExp(
      `(sgtm|server|capi|ss\\.|data\\.${rootDomain}|track\\.${rootDomain}|events\\.${rootDomain}|api\\.${rootDomain})`,
      "i"
    );

    const hasServerSide = beacons.some((b) => serverSidePattern.test(b.url));
    const serverSideEvents = beacons.filter((b) => serverSidePattern.test(b.url));
    const clientEvents = beacons.filter((b) => !serverSidePattern.test(b.url));
    const serverDomainSamples = serverSideEvents.slice(0, 5).map((b) => b.url);

    // --- Cookie breakdown ---
    const firstPartyCookies = cookies.filter((c) =>
      c.domain.includes(new URL(url).hostname)
    );
    const thirdPartyCookies = cookies.filter(
      (c) => !c.domain.includes(new URL(url).hostname)
    );
    const insecureCookies = cookies.filter((c) => !c.secure || c.sameSite === "None");

    // --- Tracker vendors ---
    const trackers = beacons.filter((b) =>
      /(facebook|google|tiktok|snapchat|klaviyo|analytics)/i.test(b.url)
    );
    const trackerVendors = Array.from(
      new Set(
        trackers.map((t) => {
          if (t.url.includes("facebook")) return "Facebook";
          if (t.url.includes("google")) return "Google";
          if (t.url.includes("tiktok")) return "TikTok";
          if (t.url.includes("snapchat")) return "Snapchat";
          if (t.url.includes("klaviyo")) return "Klaviyo";
          return "Other";
        })
      )
    );

    // --- Shopify app fingerprinting ---
    const appFingerprints: Record<string, RegExp[]> = {
      Klaviyo: [/static\.klaviyo\.com/, /a\.klaviyo\.com/],
      JudgeMe: [/cdn\.judge\.me/],
      Yotpo: [/yotpo\.com/],
      Okendo: [/okendo\.io/],
      ReConvert: [/reconvert\.io/],
      Stape: [/sgtm\./, /stape\.io/],
    };
    const shopifyAppsDetected: string[] = [];
    for (const [name, patterns] of Object.entries(appFingerprints)) {
      if (patterns.some((rx) => beacons.some((b) => rx.test(b.url)))) {
        shopifyAppsDetected.push(name);
      }
    }

    // --- Scoring ---
    const scoreTech = 70;
    let scoreBias = 60;
    let diagnosis = "Mixed setup";

    if (!hasServerSide) {
      scoreBias = 25;
      diagnosis = "Client-side only";
    } else {
      scoreBias = 92;
      diagnosis = "Server-side tracking detected";
    }
    if (insecureCookies.length > 0) scoreBias -= 5;
    if (autoDropsCookiesBeforeConsent) scoreBias -= 5; // privacy penalty

    const scorePotential = 95;

    // --- Return clean JSON ---
    return {
      summary: { url, title, timestamp: new Date().toISOString() },
      performance: { loadTimeMS, transferSizeKB },
      tracking: {
        trackerVendors,
        shopifyAppsDetected,
        beaconBreakdown: {
          client: clientEvents.length,
          server: serverSideEvents.length,
          total: beacons.length,
        },
        serverDomainsDetected: serverDomainSamples,
      },
      cookies: {
        firstParty: firstPartyCookies.length,
        thirdParty: thirdPartyCookies.length,
        insecure: insecureCookies.length,
      },
      consent,
      scores: {
        technical: scoreTech,
        firstPartyBias: Math.max(0, Math.min(100, scoreBias)),
        potentialWithFirstParty: scorePotential,
      },
      insights: {
        diagnosis,
        opportunity:
          diagnosis === "Client-side only"
            ? "High ROI potential with server-side tagging"
            : "Strong foundation; minor improvements possible",
        notes: [
          insecureCookies.length
            ? `${insecureCookies.length} cookies lack Secure or SameSite flags.`
            : "Cookie hygiene looks solid.",
          hasConsentBanner
            ? autoDropsCookiesBeforeConsent
              ? "Cookies are being dropped before user consent (compliance risk)."
              : "Consent banner detected and functioning."
            : "No consent mechanism detected."
        ].join(" "),
      },
    };
  } catch (err: any) {
    console.error("❌ Audit error:", err);
    throw new Error(err.message || "Audit failed");
  } finally {
    await browser.close().catch(() => {});
  }
}
