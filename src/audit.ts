import {
  chromium,
  type Browser,
  type Request,
  type Response,
} from "playwright";
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
  };
}

// ============================================================================
// COOKIE CATALOG - The source of truth for tracking cookies
// ============================================================================

interface CookieDefinition {
  name: string;
  provider: TrackingProvider;
  category: "Ads" | "Analytics";
  identifierPatterns?: RegExp[];
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
// COOKIE CLASSIFICATION
// ============================================================================

function classifyCookie(cookie: Cookie, rootDomain: string): NormalizedCookie {
  // Determine host type
  const cookieDomain = cookie.domain.startsWith(".")
    ? cookie.domain.substring(1)
    : cookie.domain;

  let hostType: "root" | "firstPartySubdomain" | "thirdParty";

  if (cookieDomain === rootDomain) {
    hostType = "root";
  } else if (cookieDomain.endsWith(`.${rootDomain}`)) {
    hostType = "firstPartySubdomain";
  } else {
    hostType = "thirdParty";
  }

  // Match against catalog
  let provider: TrackingProvider = "Unknown";
  let category: "Ads" | "Analytics" = "Analytics";

  for (const def of COOKIE_CATALOG) {
    if (cookie.name === def.name || cookie.name.startsWith(def.name)) {
      provider = def.provider;
      category = def.category;
      break;
    }
  }

  // Calculate lifetime in days
  const lifetimeDays =
    cookie.expires === -1
      ? 0 // Session cookie
      : Math.round((cookie.expires - Date.now()) / (1000 * 60 * 60 * 24));

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
  // Must match catalog OR contain known identifiers
  if (normalized.provider !== "Unknown") {
    return true;
  }

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
    if (capture.method !== "POST" && !capture.url.includes("?")) {
      continue;
    }

    const captureHostname = new URL(capture.url).hostname;
    const isFirstParty =
      captureHostname === rootDomain ||
      captureHostname.endsWith(`.${rootDomain}`);

    // Check for identifiers in URL or POST body
    const identifiersFound: string[] = [];
    const searchText = capture.url + (capture.postData || "");

    for (const identifier of KNOWN_IDENTIFIERS) {
      if (searchText.includes(identifier)) {
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
        identifiersFound,
      });
    }
  }

  return signals;
}

// ============================================================================
// PLATFORM SCORING
// ============================================================================

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

  let score = 0;
  let signal: "Weak" | "Strong" | "None" = "None";

  // HARD CAP: No first-party cookies = low ceiling
  if (firstPartyCookies.length === 0) {
    score = Math.min(score, 35);
    signal = "None";

    return {
      platform: provider,
      score,
      signal,
      estimatedRevenueLoss: "25-40%",
      resolveCTA: `Deploy first-party ${provider} cookies via server-side tagging`,
      hasFirstPartyCookies: false,
      hasServerSideRouting: false,
    };
  }

  // Cookie quality score (0-70 points)
  const cookieScore = calculateCookieScore(
    firstPartyCookies,
    platformCookies.length,
  );
  score += cookieScore;

  // Routing score (0-30 points)
  if (firstPartyRouting.length > 0) {
    score += 30;
    signal = "Strong";
  } else if (platformRouting.length > 0) {
    // Has routing but not first-party
    score += 10;
    signal = "Weak";
  } else {
    // No routing detected
    signal = "Weak";
  }

  // Determine revenue loss and CTA
  let estimatedRevenueLoss: string;
  let resolveCTA: string;

  if (score >= 80) {
    estimatedRevenueLoss = "0-5%";
    resolveCTA = "Optimization: Monitor cookie lifetime and consent rates";
  } else if (score >= 60) {
    estimatedRevenueLoss = "5-15%";
    resolveCTA = `Strengthen ${provider} server-side routing`;
  } else if (score >= 40) {
    estimatedRevenueLoss = "15-25%";
    resolveCTA = `Deploy server-side tagging for ${provider}`;
  } else {
    estimatedRevenueLoss = "25-40%";
    resolveCTA = `Critical: Implement first-party ${provider} infrastructure`;
  }

  return {
    platform: provider,
    score: Math.round(score),
    signal,
    estimatedRevenueLoss,
    resolveCTA,
    hasFirstPartyCookies: firstPartyCookies.length > 0,
    hasServerSideRouting: firstPartyRouting.length > 0,
  };
}

function calculateCookieScore(
  firstPartyCookies: NormalizedCookie[],
  totalPlatformCookies: number,
): number {
  if (totalPlatformCookies === 0) return 0;

  // Base: percentage that are first-party (0-40 points)
  const firstPartyRatio = firstPartyCookies.length / totalPlatformCookies;
  let score = firstPartyRatio * 40;

  // Lifetime quality (0-20 points)
  const avgLifetime =
    firstPartyCookies.reduce((sum, c) => sum + c.lifetimeDays, 0) /
    firstPartyCookies.length;

  if (avgLifetime >= 365) {
    score += 20;
  } else if (avgLifetime >= 180) {
    score += 15;
  } else if (avgLifetime >= 90) {
    score += 10;
  } else if (avgLifetime >= 30) {
    score += 5;
  }

  // Security flags (0-10 points)
  const secureCount = firstPartyCookies.filter((c) => c.secure).length;
  const httpOnlyCount = firstPartyCookies.filter((c) => c.httpOnly).length;

  score += (secureCount / firstPartyCookies.length) * 5;
  score += (httpOnlyCount / firstPartyCookies.length) * 5;

  return score;
}

// ============================================================================
// OVERALL SCORING
// ============================================================================

function calculateOverallScore(
  cookies: NormalizedCookie[],
  routingSignals: RoutingSignal[],
  pageLoadTime: number,
): number {
  const trackingCookies = cookies.filter(isTrackingCookie);
  const firstPartyTrackingCookies = trackingCookies.filter(
    (c) => c.hostType === "root" || c.hostType === "firstPartySubdomain",
  );

  // HARD CAP: No first-party tracking cookies
  if (firstPartyTrackingCookies.length === 0) {
    return Math.min(
      50,
      calculateRawScore(cookies, routingSignals, pageLoadTime),
    );
  }

  return calculateRawScore(cookies, routingSignals, pageLoadTime);
}

function calculateRawScore(
  cookies: NormalizedCookie[],
  routingSignals: RoutingSignal[],
  pageLoadTime: number,
): number {
  const trackingCookies = cookies.filter(isTrackingCookie);
  const firstPartyTrackingCookies = trackingCookies.filter(
    (c) => c.hostType === "root" || c.hostType === "firstPartySubdomain",
  );

  // Tracking score (0-90 points)
  let trackingScore = 0;

  if (trackingCookies.length > 0) {
    // Cookie ratio (0-50 points)
    const firstPartyRatio =
      firstPartyTrackingCookies.length / trackingCookies.length;
    trackingScore += firstPartyRatio * 50;

    // Average lifetime (0-20 points)
    if (firstPartyTrackingCookies.length > 0) {
      const avgLifetime =
        firstPartyTrackingCookies.reduce((sum, c) => sum + c.lifetimeDays, 0) /
        firstPartyTrackingCookies.length;

      if (avgLifetime >= 365) trackingScore += 20;
      else if (avgLifetime >= 180) trackingScore += 15;
      else if (avgLifetime >= 90) trackingScore += 10;
      else if (avgLifetime >= 30) trackingScore += 5;
    }

    // Routing quality (0-20 points)
    const firstPartyRouting = routingSignals.filter((s) => s.isFirstParty);
    if (firstPartyRouting.length >= 3) {
      trackingScore += 20;
    } else if (firstPartyRouting.length >= 2) {
      trackingScore += 15;
    } else if (firstPartyRouting.length >= 1) {
      trackingScore += 10;
    } else if (routingSignals.length > 0) {
      trackingScore += 5;
    }
  }

  // Page speed score (0-10 points)
  let pageSpeedScore = 10;
  if (pageLoadTime > 3000) {
    pageSpeedScore = 5;
  } else if (pageLoadTime > 2000) {
    pageSpeedScore = 8;
  }

  // Final composition
  const finalScore = trackingScore * 0.9 + pageSpeedScore * 0.1;

  return Math.round(Math.min(100, Math.max(0, finalScore)));
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
    if (platform.score < 60) {
      recommendations.push(platform.resolveCTA);
    }
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
// MAIN AUDIT FUNCTION
// ============================================================================

async function safeGoto(
  page: any,
  url: string,
  timeout: number = 15000,
): Promise<number> {
  const startTime = Date.now();

  try {
    // Try networkidle first with shorter timeout
    await page.goto(url, {
      waitUntil: "networkidle",
      timeout: timeout,
    });
  } catch (error: any) {
    if (error.message?.includes("Timeout")) {
      // Fallback to 'load' event which is more forgiving
      try {
        await page.goto(url, {
          waitUntil: "load",
          timeout: timeout,
        });
      } catch (loadError: any) {
        if (loadError.message?.includes("Timeout")) {
          // Final fallback: just wait for DOM content
          await page.goto(url, {
            waitUntil: "domcontentloaded",
            timeout: timeout,
          });
        } else {
          throw loadError;
        }
      }
    } else {
      throw error;
    }
  }

  return Date.now() - startTime;
}

export async function runAudit(url: string): Promise<AuditResult> {
  let browser: Browser | null = null;

  try {
    // Parse root domain
    const parsedUrl = new URL(url);
    const tldParsed = parseTld(parsedUrl.hostname);
    const rootDomain = tldParsed.domain || parsedUrl.hostname;

    browser = await chromium.launch({
      headless: true,
      args: ["--disable-dev-shm-usage", "--no-sandbox"],
    });

    const context = await browser.newContext({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    });

    const page = await context.newPage();

    // Set default navigation timeout
    page.setDefaultNavigationTimeout(20000);
    page.setDefaultTimeout(20000);

    // Network capture
    const networkCaptures: NetworkCapture[] = [];

    page.on("request", (request: Request) => {
      const postData = request.postData();
      networkCaptures.push({
        url: request.url(),
        method: request.method(),
        host: new URL(request.url()).hostname,
        headers: request.headers(),
        postData: postData || undefined,
        timestamp: Date.now(),
        resourceType: request.resourceType(),
      });
    });

    // Pass 1: Normal visit
    const pageLoadTime = await safeGoto(page, url, 15000);

    // Wait for any delayed tracking scripts
    await page.waitForTimeout(1500);

    // Pass 2: Synthetic click IDs
    const urlWithClickIds = new URL(url);
    urlWithClickIds.searchParams.set("gclid", "test_gclid_123");
    urlWithClickIds.searchParams.set("fbclid", "test_fbclid_456");

    try {
      await safeGoto(page, urlWithClickIds.toString(), 10000);
      // Wait for async tracking
      await page.waitForTimeout(1500);
    } catch (error) {
      // If second pass fails, continue with data from first pass
      console.warn(
        "Second pass with click IDs failed, continuing with first pass data",
      );
    }

    // Capture cookies
    const rawCookies = await context.cookies();

    await browser.close();
    browser = null;

    // Classify cookies
    const normalizedCookies = rawCookies.map((c) =>
      classifyCookie(c, rootDomain),
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

    // Calculate overall score
    const overallScore = calculateOverallScore(
      normalizedCookies,
      routingSignals,
      pageLoadTime,
    );
    const letterGrade = getLetterGrade(overallScore);

    // Generate recommendations
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
      },
    };
  } catch (error) {
    if (browser) {
      await browser.close();
    }
    throw error;
  }
}
