// audit.ts
import { chromium, type Browser, type Request } from "playwright";
import { parse as parseTld } from "tldts";

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

interface Cookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number;
  httpOnly: boolean;
  secure: boolean;
  sameSite: "Strict" | "Lax" | "None";
}

interface NormalizedCookie {
  name: string;
  domain: string;
  provider: TrackingProvider;
  category: "Ads" | "Analytics";
  lifetimeDays: number;
  hostType: "root" | "firstPartySubdomain" | "thirdParty";
  secure: boolean;
  httpOnly: boolean;
}

type TrackingProvider =
  | "Meta"
  | "Google Analytics"
  | "Google Ads"
  | "TikTok"
  | "Unknown";

interface NetworkCapture {
  url: string;
  method: string;
  host: string;
  headers: Record<string, string>;
  postData?: string;
  timestamp: number;
  resourceType: string;
}

interface RoutingSignal {
  provider: TrackingProvider;
  endpoint: string;
  isFirstParty: boolean;
  hasIdentifiers: boolean;
  identifiersFound: string[];
}

interface PlatformScore {
  platform: TrackingProvider;
  score: number;
  signal: "Weak" | "Strong" | "None";
  estimatedRevenueLoss: string;
  resolveCTA: string;
  hasFirstPartyCookies: boolean;
  hasServerSideRouting: boolean;
}

interface AuditResult {
  overallScore: number;
  letterGrade: string;
  platformScores: PlatformScore[];
  recommendedActions: string;
  debugInfo: {
    totalCookies: number;
    firstPartyCookies: number;
    thirdPartyCookies: number;
    trackingCookies: number;
    routingSignals: RoutingSignal[];
    pageLoadTime: number;
    // extra guardrails so you can see why a job timed out
    captureCounts: {
      total: number;
      http: number;
      skippedNonHttp: number;
      capped: boolean;
    };
  };
}

// ============================================================================
// COOKIE CATALOG - The source of truth for tracking cookies
// ============================================================================

interface CookieDefinition {
  name: string;
  provider: TrackingProvider;
  category: "Ads" | "Analytics";
}

const COOKIE_CATALOG: CookieDefinition[] = [
  // Meta
  { name: "_fbp", provider: "Meta", category: "Analytics" },
  { name: "_fbc", provider: "Meta", category: "Ads" },
  { name: "fr", provider: "Meta", category: "Ads" },

  // Google Analytics
  { name: "_ga", provider: "Google Analytics", category: "Analytics" },
  { name: "_ga_", provider: "Google Analytics", category: "Analytics" },
  { name: "_gid", provider: "Google Analytics", category: "Analytics" },
  { name: "_gat", provider: "Google Analytics", category: "Analytics" },

  // Google Ads
  { name: "_gcl_au", provider: "Google Ads", category: "Ads" },
  { name: "_gcl_aw", provider: "Google Ads", category: "Ads" },
  { name: "_gcl_dc", provider: "Google Ads", category: "Ads" },

  // TikTok
  { name: "_ttp", provider: "TikTok", category: "Analytics" },
  { name: "_tt_enable_cookie", provider: "TikTok", category: "Ads" },
  { name: "ttclid", provider: "TikTok", category: "Ads" },
];

const KNOWN_IDENTIFIERS = [
  "_ga",
  "_fbp",
  "_fbc",
  "gclid",
  "fbclid",
  "ttclid",
  "client_id",
  "user_id",
  "session_id",
  "_gcl_aw",
];

// ============================================================================
// SMALL UTILS / GUARDS
// ============================================================================

function normalizeInputUrl(input: string): string {
  const t = (input || "").trim();
  if (!t) throw new Error("Missing URL");
  return t.startsWith("http://") || t.startsWith("https://")
    ? t
    : `https://${t}`;
}

function isHttpUrl(u: string): boolean {
  return u.startsWith("http://") || u.startsWith("https://");
}

function safeHostname(u: string): string | null {
  if (!isHttpUrl(u)) return null;
  try {
    return new URL(u).hostname;
  } catch {
    return null;
  }
}

function withHardTimeout<T>(
  promiseFactory: () => Promise<T>,
  ms: number,
  onTimeout?: () => Promise<void>,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(async () => {
      try {
        if (onTimeout) await onTimeout();
      } finally {
        reject(new Error(`Audit hard-timed-out after ${ms}ms`));
      }
    }, ms);

    promiseFactory()
      .then((v) => {
        clearTimeout(t);
        resolve(v);
      })
      .catch((e) => {
        clearTimeout(t);
        reject(e);
      });
  });
}

// ============================================================================
// COOKIE CLASSIFICATION
// ============================================================================

function classifyCookie(cookie: Cookie, rootDomain: string): NormalizedCookie {
  const cookieDomain = cookie.domain.startsWith(".")
    ? cookie.domain.substring(1)
    : cookie.domain;

  let hostType: "root" | "firstPartySubdomain" | "thirdParty";
  if (cookieDomain === rootDomain) hostType = "root";
  else if (cookieDomain.endsWith(`.${rootDomain}`))
    hostType = "firstPartySubdomain";
  else hostType = "thirdParty";

  let provider: TrackingProvider = "Unknown";
  let category: "Ads" | "Analytics" = "Analytics";

  for (const def of COOKIE_CATALOG) {
    if (cookie.name === def.name || cookie.name.startsWith(def.name)) {
      provider = def.provider;
      category = def.category;
      break;
    }
  }

  // Playwright gives expires in UNIX seconds; some cookie typings use ms.
  // We treat values > 10^10 as ms and <= 10^10 as seconds.
  const expiresMs =
    cookie.expires <= 0
      ? -1
      : cookie.expires > 10_000_000_000
        ? cookie.expires
        : cookie.expires * 1000;

  const lifetimeDays =
    expiresMs === -1
      ? 0
      : Math.max(
          0,
          Math.round((expiresMs - Date.now()) / (1000 * 60 * 60 * 24)),
        );

  return {
    name: cookie.name,
    domain: cookieDomain,
    provider,
    category,
    lifetimeDays,
    hostType,
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
  };
}

function isTrackingCookie(normalized: NormalizedCookie): boolean {
  if (normalized.provider !== "Unknown") return true;
  return KNOWN_IDENTIFIERS.some((id) => normalized.name.includes(id));
}

// ============================================================================
// ROUTING DETECTION - The server-side signal
// ============================================================================

function detectRoutingSignals(
  networkCaptures: NetworkCapture[],
  rootDomain: string,
): RoutingSignal[] {
  const signals: RoutingSignal[] = [];

  for (const capture of networkCaptures) {
    // Only analyze POST requests or requests with query params
    if (capture.method !== "POST" && !capture.url.includes("?")) continue;

    const captureHostname = safeHostname(capture.url);
    if (!captureHostname) continue;

    const isFirstParty =
      captureHostname === rootDomain ||
      captureHostname.endsWith(`.${rootDomain}`);

    const identifiersFound: string[] = [];
    const searchText = (capture.url + (capture.postData || "")).toLowerCase();

    for (const identifier of KNOWN_IDENTIFIERS) {
      if (searchText.includes(identifier.toLowerCase())) {
        identifiersFound.push(identifier);
      }
    }

    // Determine provider from hostname
    let provider: TrackingProvider = "Unknown";
    const hostname = captureHostname.toLowerCase();

    if (hostname.includes("facebook") || hostname.includes("fbcdn")) {
      provider = "Meta";
    } else if (
      hostname.includes("google-analytics") ||
      hostname.includes("analytics.google")
    ) {
      provider = "Google Analytics";
    } else if (
      hostname.includes("googleadservices") ||
      hostname.includes("doubleclick")
    ) {
      provider = "Google Ads";
    } else if (hostname.includes("tiktok") || hostname.includes("bytedance")) {
      provider = "TikTok";
    }

    if (identifiersFound.length > 0) {
      signals.push({
        provider,
        endpoint: capture.url,
        isFirstParty,
        hasIdentifiers: true,
        identifiersFound: Array.from(new Set(identifiersFound)),
      });
    }
  }

  return signals;
}

// ============================================================================
// PLATFORM SCORING
// ============================================================================

function calculateCookieScore(
  firstPartyCookies: NormalizedCookie[],
  totalPlatformCookies: number,
): number {
  if (totalPlatformCookies === 0) return 0;

  const firstPartyRatio = firstPartyCookies.length / totalPlatformCookies;
  let score = firstPartyRatio * 40;

  const avgLifetime =
    firstPartyCookies.reduce((sum, c) => sum + c.lifetimeDays, 0) /
    Math.max(1, firstPartyCookies.length);

  if (avgLifetime >= 365) score += 20;
  else if (avgLifetime >= 180) score += 15;
  else if (avgLifetime >= 90) score += 10;
  else if (avgLifetime >= 30) score += 5;

  const secureCount = firstPartyCookies.filter((c) => c.secure).length;
  const httpOnlyCount = firstPartyCookies.filter((c) => c.httpOnly).length;

  score += (secureCount / Math.max(1, firstPartyCookies.length)) * 5;
  score += (httpOnlyCount / Math.max(1, firstPartyCookies.length)) * 5;

  return score;
}

function scorePlatform(
  provider: TrackingProvider,
  cookies: NormalizedCookie[],
  routingSignals: RoutingSignal[],
): PlatformScore {
  const platformCookies = cookies.filter((c) => c.provider === provider);
  const firstPartyCookies = platformCookies.filter(
    (c) => c.hostType === "root" || c.hostType === "firstPartySubdomain",
  );

  const platformRouting = routingSignals.filter((s) => s.provider === provider);
  const firstPartyRouting = platformRouting.filter((s) => s.isFirstParty);

  // HARD CAP: No first-party cookies = low ceiling
  if (firstPartyCookies.length === 0) {
    return {
      platform: provider,
      score: 35,
      signal: "None",
      estimatedRevenueLoss: "25-40%",
      resolveCTA: `Deploy first-party ${provider} cookies via server-side tagging`,
      hasFirstPartyCookies: false,
      hasServerSideRouting: false,
    };
  }

  let score = 0;
  let signal: "Weak" | "Strong" | "None" = "Weak";

  score += calculateCookieScore(firstPartyCookies, platformCookies.length);

  if (firstPartyRouting.length > 0) {
    score += 30;
    signal = "Strong";
  } else if (platformRouting.length > 0) {
    score += 10;
    signal = "Weak";
  } else {
    score += 0;
    signal = "Weak";
  }

  let estimatedRevenueLoss = "25-40%";
  let resolveCTA = `Critical: Implement first-party ${provider} infrastructure`;

  if (score >= 80) {
    estimatedRevenueLoss = "0-5%";
    resolveCTA = "Optimization: Monitor cookie lifetime and consent rates";
  } else if (score >= 60) {
    estimatedRevenueLoss = "5-15%";
    resolveCTA = `Strengthen ${provider} server-side routing`;
  } else if (score >= 40) {
    estimatedRevenueLoss = "15-25%";
    resolveCTA = `Deploy server-side tagging for ${provider}`;
  }

  return {
    platform: provider,
    score: Math.round(Math.min(100, Math.max(0, score))),
    signal,
    estimatedRevenueLoss,
    resolveCTA,
    hasFirstPartyCookies: true,
    hasServerSideRouting: firstPartyRouting.length > 0,
  };
}

// ============================================================================
// OVERALL SCORING
// ============================================================================

function calculateRawScore(
  cookies: NormalizedCookie[],
  routingSignals: RoutingSignal[],
  pageLoadTime: number,
): number {
  const trackingCookies = cookies.filter(isTrackingCookie);
  const firstPartyTrackingCookies = trackingCookies.filter(
    (c) => c.hostType === "root" || c.hostType === "firstPartySubdomain",
  );

  let trackingScore = 0;

  if (trackingCookies.length > 0) {
    const firstPartyRatio =
      firstPartyTrackingCookies.length / Math.max(1, trackingCookies.length);
    trackingScore += firstPartyRatio * 50;

    if (firstPartyTrackingCookies.length > 0) {
      const avgLifetime =
        firstPartyTrackingCookies.reduce((sum, c) => sum + c.lifetimeDays, 0) /
        Math.max(1, firstPartyTrackingCookies.length);

      if (avgLifetime >= 365) trackingScore += 20;
      else if (avgLifetime >= 180) trackingScore += 15;
      else if (avgLifetime >= 90) trackingScore += 10;
      else if (avgLifetime >= 30) trackingScore += 5;
    }

    const firstPartyRouting = routingSignals.filter((s) => s.isFirstParty);
    if (firstPartyRouting.length >= 3) trackingScore += 20;
    else if (firstPartyRouting.length >= 2) trackingScore += 15;
    else if (firstPartyRouting.length >= 1) trackingScore += 10;
    else if (routingSignals.length > 0) trackingScore += 5;
  }

  // pageSpeed is light and can’t hang the job
  let pageSpeedScore = 10;
  if (pageLoadTime > 3000) pageSpeedScore = 5;
  else if (pageLoadTime > 2000) pageSpeedScore = 8;

  const finalScore = trackingScore * 0.9 + pageSpeedScore * 0.1;
  return Math.round(Math.min(100, Math.max(0, finalScore)));
}

function calculateOverallScore(
  cookies: NormalizedCookie[],
  routingSignals: RoutingSignal[],
  pageLoadTime: number,
): number {
  const trackingCookies = cookies.filter(isTrackingCookie);
  const firstPartyTrackingCookies = trackingCookies.filter(
    (c) => c.hostType === "root" || c.hostType === "firstPartySubdomain",
  );

  if (firstPartyTrackingCookies.length === 0) {
    return Math.min(
      50,
      calculateRawScore(cookies, routingSignals, pageLoadTime),
    );
  }

  return calculateRawScore(cookies, routingSignals, pageLoadTime);
}

function getLetterGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

// ============================================================================
// RECOMMENDED ACTIONS
// ============================================================================

function generateRecommendations(
  overallScore: number,
  platformScores: PlatformScore[],
  cookies: NormalizedCookie[],
): string {
  const recommendations: string[] = [];

  const trackingCookies = cookies.filter(isTrackingCookie);
  const firstPartyTrackingCookies = trackingCookies.filter(
    (c) => c.hostType === "root" || c.hostType === "firstPartySubdomain",
  );

  if (firstPartyTrackingCookies.length === 0) {
    recommendations.push(
      "CRITICAL: No first-party tracking cookies detected. Implement server-side tagging immediately to prevent 25-40% revenue loss.",
    );
  }

  for (const platform of platformScores) {
    if (platform.score < 60) recommendations.push(platform.resolveCTA);
  }

  if (overallScore < 70) {
    recommendations.push(
      "Consider migrating to a server-side tracking architecture (e.g., Stape, Elevar, or custom GTM Server)",
    );
  }

  const shortLifetimeCookies = firstPartyTrackingCookies.filter(
    (c) => c.lifetimeDays < 90,
  );
  if (shortLifetimeCookies.length > 0) {
    recommendations.push(
      `Extend cookie lifetime for ${shortLifetimeCookies.length} tracking cookie(s) to at least 365 days for better attribution`,
    );
  }

  if (recommendations.length === 0) {
    return "Your tracking setup is strong. Continue monitoring cookie consent rates and server-side routing performance.";
  }

  return recommendations.join(" ");
}

// ============================================================================
// NAVIGATION (won’t get stuck)
// ============================================================================

async function safeGoto(page: any, url: string): Promise<number> {
  const start = Date.now();

  const strategies = [
    { waitUntil: "networkidle" as const, timeout: 10_000 },
    { waitUntil: "load" as const, timeout: 15_000 },
    { waitUntil: "domcontentloaded" as const, timeout: 20_000 },
    { waitUntil: "commit" as const, timeout: 25_000 },
  ];

  for (const s of strategies) {
    try {
      await page.goto(url, { waitUntil: s.waitUntil, timeout: s.timeout });
      return Date.now() - start;
    } catch (e: any) {
      const msg = String(e?.message || e);
      if (!msg.toLowerCase().includes("timeout")) throw e;
      // try next strategy
    }
  }

  // Proceed with partial load
  return Date.now() - start;
}

// ============================================================================
// MAIN AUDIT FUNCTION (bulletproof against hanging jobs)
// ============================================================================

export async function runAudit(url: string): Promise<AuditResult> {
  const normalizedUrl = normalizeInputUrl(url);

  let browser: Browser | null = null;

  // capture limits (prevents memory spiral)
  const CAPTURE_LIMIT = 5000;
  const POSTDATA_LIMIT = 20_000;

  // capture counters for debug
  const captureCounts = {
    total: 0,
    http: 0,
    skippedNonHttp: 0,
    capped: false,
  };

  return withHardTimeout(
    async () => {
      // Parse root domain (safe)
      const parsedUrl = new URL(normalizedUrl);
      const tldParsed = parseTld(parsedUrl.hostname);
      const rootDomain = tldParsed.domain || parsedUrl.hostname;

      browser = await chromium.launch({
        headless: true,
        args: ["--disable-dev-shm-usage", "--no-sandbox"],
      });

      const context = await browser.newContext({
        userAgent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ignoreHTTPSErrors: true,
      });

      const page = await context.newPage();
      page.setDefaultNavigationTimeout(30_000);
      page.setDefaultTimeout(30_000);

      const networkCaptures: NetworkCapture[] = [];

      // SAFE request capture: ignores non-http URLs; caps size; caps count
      page.on("request", (request: Request) => {
        captureCounts.total += 1;

        const reqUrl = request.url();
        if (!isHttpUrl(reqUrl)) {
          captureCounts.skippedNonHttp += 1;
          return;
        }

        const host = safeHostname(reqUrl);
        if (!host) {
          captureCounts.skippedNonHttp += 1;
          return;
        }

        captureCounts.http += 1;

        const rawPost = request.postData() || "";
        const postData =
          rawPost && rawPost.length > POSTDATA_LIMIT
            ? rawPost.slice(0, POSTDATA_LIMIT)
            : rawPost;

        const headers = request.headers();
        const keepHeaders: Record<string, string> = {};
        for (const k of ["content-type", "referer", "origin", "user-agent"]) {
          if (headers[k]) keepHeaders[k] = headers[k];
        }

        networkCaptures.push({
          url: reqUrl,
          method: request.method(),
          host,
          headers: keepHeaders,
          postData: postData || undefined,
          timestamp: Date.now(),
          resourceType: request.resourceType(),
        });

        if (networkCaptures.length > CAPTURE_LIMIT) {
          networkCaptures.shift();
          captureCounts.capped = true;
        }
      });

      // Pass 1: Normal visit
      let pageLoadTime = 0;
      try {
        pageLoadTime = await safeGoto(page, normalizedUrl);
      } catch (e: any) {
        console.warn("Navigation failed, continuing:", e?.message || e);
        pageLoadTime = 30_000;
      }

      await page.waitForTimeout(2000).catch(() => {});

      // Pass 2: Synthetic click IDs (best effort)
      try {
        const urlWithClickIds = new URL(normalizedUrl);
        urlWithClickIds.searchParams.set("gclid", "test_gclid_123");
        urlWithClickIds.searchParams.set("fbclid", "test_fbclid_456");

        await safeGoto(page, urlWithClickIds.toString());
        await page.waitForTimeout(2000).catch(() => {});
      } catch {
        // ignore
      }

      // Cookies
      const rawCookies = await context.cookies();

      // Always attempt close quickly after we’ve got data
      await browser.close().catch(() => {});
      browser = null;

      // Classify cookies
      const normalizedCookies = rawCookies.map((c) =>
        classifyCookie(c as unknown as Cookie, rootDomain),
      );

      const trackingCookies = normalizedCookies.filter(isTrackingCookie);
      const firstPartyCookies = normalizedCookies.filter(
        (c) => c.hostType === "root" || c.hostType === "firstPartySubdomain",
      );
      const thirdPartyCookies = normalizedCookies.filter(
        (c) => c.hostType === "thirdParty",
      );

      // Detect routing
      const routingSignals = detectRoutingSignals(networkCaptures, rootDomain);

      // Score platforms
      const providers: TrackingProvider[] = [
        "Meta",
        "Google Analytics",
        "Google Ads",
        "TikTok",
      ];

      const platformScores = providers
        .map((provider) =>
          scorePlatform(provider, normalizedCookies, routingSignals),
        )
        .filter((ps) => ps.hasFirstPartyCookies || ps.hasServerSideRouting);

      // Overall score
      const overallScore = calculateOverallScore(
        normalizedCookies,
        routingSignals,
        pageLoadTime,
      );
      const letterGrade = getLetterGrade(overallScore);

      // Recommendations
      const recommendedActions = generateRecommendations(
        overallScore,
        platformScores,
        normalizedCookies,
      );

      return {
        overallScore,
        letterGrade,
        platformScores,
        recommendedActions,
        debugInfo: {
          totalCookies: normalizedCookies.length,
          firstPartyCookies: firstPartyCookies.length,
          thirdPartyCookies: thirdPartyCookies.length,
          trackingCookies: trackingCookies.length,
          routingSignals,
          pageLoadTime,
          captureCounts,
        },
      };
    },
    120_000, // hard cap per audit so worker never stays "running" forever
    async () => {
      if (browser) {
        try {
          await browser.close();
        } catch {}
        browser = null;
      }
    },
  );
}
