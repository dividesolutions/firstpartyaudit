import {
  chromium,
  type Browser,
  type Request,
  type Response,
} from "playwright";
import { parse as parseTld } from "tldts";

/**
 * First-Party Site Scanner (tracking-first)
 *
 * Core philosophy implemented:
 * - First-party tracking cookies earn points (root or first-party subdomain).
 * - Third-party cookies are tracked but score-neutral.
 * - Server-side is inferred ONLY via first-party routed collection evidence (POSTs to root/FP subdomain with IDs).
 * - ~90% of overall score is cookies + routing, page speed is a light modifier.
 * - Hard cap: if zero first-party tracking cookies, overall cannot exceed 50; platform scores tank.
 *
 * Usage:
 *   const result = await runAudit("https://example.com");
 *   console.log(JSON.stringify(result, null, 2));
 */

// -----------------------------
// Types
// -----------------------------
type Platform =
  | "Meta"
  | "Google Analytics"
  | "Google Ads"
  | "TikTok"
  | "Unknown";
type Category = "Ads" | "Analytics";
type HostType = "root" | "firstPartySubdomain" | "thirdParty";
type SignalStrength = "None" | "Weak" | "Strong";
type Grade = "A" | "B" | "C" | "D" | "F";

type CookieRecord = {
  name: string;
  valuePreview?: string;
  domain: string; // as observed in Set-Cookie (or fallback)
  path?: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  maxAge?: number | null;
  expires?: string | null;
  lifetimeDays: number | null;

  provider: Platform;
  category: Category;
  hostType: HostType;

  // convenience
  isTracking: boolean; // catalog or identifier-derived
  isFirstPartyTracking: boolean; // isTracking && (root|firstPartySubdomain)
  isThirdPartyTracking: boolean; // isTracking && thirdParty
};

type RequestEvidence = {
  url: string;
  method: string;
  hostname: string;
  hostType: HostType;
  isPost: boolean;
  contentType?: string;
  postBodyBytes?: number;
  containsIdentifiers: {
    gclid: boolean;
    fbclid: boolean;
    fbp: boolean;
    fbc: boolean;
    gaClient: boolean;
    ttp: boolean;
    genericId: boolean;
  };
  platformDirect: Partial<Record<Platform, boolean>>;
};

type PlatformReport = {
  platform: Exclude<Platform, "Unknown">;
  score: number; // 0-100
  signal: SignalStrength;
  estimatedRevenueLoss: "Low" | "Medium" | "High";
  resolveCTA: string;
  debug: {
    fpCookies: string[];
    tpCookies: string[];
    fpRoutingPosts: number;
    directToVendors: boolean;
  };
};

type AuditDebug = {
  notes: string[];
  loadMs: number;
  pageSpeedScore: number;
  trackingScore: number;
  capsApplied: string[];
  totals: {
    cookiesSeen: number;
    trackingCookiesSeen: number;
    fpTrackingCookies: number;
    tpTrackingCookies: number;
    fpRoutingPosts: number;
    vendorDirectPosts: number;
  };
  hostBreakdown: Array<{
    hostname: string;
    hostType: HostType;
    requests: number;
    posts: number;
    setCookieResponses: number;
    cookieNames: Record<string, number>;
  }>;
};

type AuditResult = {
  url: string;
  overallScore: number;
  letterGrade: Grade;

  signal: SignalStrength; // overall routing signal
  recommendedActions: string;

  platforms: PlatformReport[];

  cookies: {
    all: CookieRecord[];
    tracking: CookieRecord[];
    firstPartyTracking: CookieRecord[];
    thirdPartyTracking: CookieRecord[];
  };

  evidence: {
    requests: RequestEvidence[];
  };

  debug: AuditDebug;
};

// -----------------------------
// Cookie catalog + identifier rules
// -----------------------------
type CookieCatalogEntry = {
  provider: Exclude<Platform, "Unknown">;
  category: Category;
  defaultLifetimeDays: number | null;
  match: (name: string) => boolean;
};

const COOKIE_CATALOG: CookieCatalogEntry[] = [
  // Meta
  {
    provider: "Meta",
    category: "Ads",
    defaultLifetimeDays: 365,
    match: (n) => n === "_fbp",
  },
  {
    provider: "Meta",
    category: "Ads",
    defaultLifetimeDays: 90,
    match: (n) => n === "_fbc",
  },

  // Google Analytics / GA4
  {
    provider: "Google Analytics",
    category: "Analytics",
    defaultLifetimeDays: 730,
    match: (n) => n === "_ga",
  },
  {
    provider: "Google Analytics",
    category: "Analytics",
    defaultLifetimeDays: 90,
    match: (n) => n.startsWith("_ga_"), // GA4 property cookie
  },

  // Google Ads (often not cookies, but some setups set them)
  {
    provider: "Google Ads",
    category: "Ads",
    defaultLifetimeDays: 90,
    match: (n) => n === "_gcl_au",
  },

  // TikTok
  {
    provider: "TikTok",
    category: "Ads",
    defaultLifetimeDays: 390,
    match: (n) => n === "_ttp",
  },
];

// Known identifier keys (URL/body/cookie/header)
const IDENTIFIER_KEYS = {
  gclid: ["gclid"],
  fbclid: ["fbclid"],
  fbp: ["_fbp", "fbp"],
  fbc: ["_fbc", "fbc"],
  gaClient: ["cid", "client_id", "_ga"],
  ttp: ["_ttp", "ttp"],
};

// Vendor endpoints (direct collection)
const VENDOR_HOST_MATCHERS: Array<{
  platform: Exclude<Platform, "Unknown">;
  match: (h: string) => boolean;
}> = [
  // Meta
  {
    platform: "Meta",
    match: (h) =>
      h.endsWith("facebook.com") ||
      h.endsWith("facebook.net") ||
      h.endsWith("fbcdn.net"),
  },
  // GA
  {
    platform: "Google Analytics",
    match: (h) =>
      h === "www.google-analytics.com" ||
      h === "google-analytics.com" ||
      h.endsWith(".google-analytics.com") ||
      h === "www.googletagmanager.com" ||
      h === "googletagmanager.com",
  },
  // Google Ads
  {
    platform: "Google Ads",
    match: (h) =>
      h === "googleads.g.doubleclick.net" ||
      h.endsWith("doubleclick.net") ||
      h.endsWith("googlesyndication.com") ||
      h.endsWith("adservice.google.com") ||
      h.endsWith("google.com"),
  },
  // TikTok
  {
    platform: "TikTok",
    match: (h) =>
      h.endsWith("tiktok.com") ||
      h.endsWith("tiktokcdn.com") ||
      h.endsWith("byteoversea.com") ||
      h.endsWith("bytedance.com"),
  },
];

// -----------------------------
// Public API
// -----------------------------
export async function runAudit(
  url: string,
  opts?: {
    timeoutMs?: number;
    twoPass?: boolean;
    syntheticClickIds?: boolean;
    headless?: boolean;
  },
): Promise<AuditResult> {
  const timeoutMs = opts?.timeoutMs ?? 45_000;
  const twoPass = opts?.twoPass ?? true;
  const syntheticClickIds = opts?.syntheticClickIds ?? true;
  const headless = opts?.headless ?? true;

  const notes: string[] = [];
  const capsApplied: string[] = [];

  const browser = await chromium.launch({ headless });
  try {
    const pass1 = await capturePass(browser, url, timeoutMs, notes);
    let pass2 = null as null | CaptureBundle;

    // Optional second pass: add click ids to URL to expose hidden routing flows
    if (twoPass && syntheticClickIds) {
      const withIds = addSyntheticClickIds(url);
      pass2 = await capturePass(browser, withIds, timeoutMs, notes, true);
    }

    const combined = mergeCaptureBundles(pass1, pass2);

    // Determine site root
    const rootDomain = getRootDomain(url);
    if (!rootDomain) {
      notes.push(
        "Could not determine root domain; treating everything as third-party.",
      );
    }

    // Cookie parsing/classification
    const allCookies = parseAndClassifyCookies(
      combined.setCookieHeaders,
      rootDomain,
    );

    // Track only scoring-relevant cookies (catalog or known identifier-based)
    const trackingCookies = allCookies.filter((c) => c.isTracking);

    const fpTrackingCookies = trackingCookies.filter(
      (c) => c.isFirstPartyTracking,
    );
    const tpTrackingCookies = trackingCookies.filter(
      (c) => c.isThirdPartyTracking,
    );

    // Request evidence + routing detection
    const reqEvidence = buildRequestEvidence(combined.requests, rootDomain);

    const routing = evaluateRouting(reqEvidence);

    // Platform reports
    const platforms: PlatformReport[] = (
      ["Meta", "Google Analytics", "Google Ads", "TikTok"] as const
    ).map((p) =>
      scorePlatform(
        p,
        trackingCookies,
        reqEvidence,
        routing.firstPartyRoutingPosts,
      ),
    );

    // Scores
    const pageSpeedScore = scorePageSpeed(combined.loadMs);
    const trackingScore = scoreTracking(
      trackingCookies,
      fpTrackingCookies,
      routing,
    );

    // Overall: 90% tracking + 10% page speed, then apply caps.
    let overallScore =
      clamp01(0.9 * (trackingScore / 100) + 0.1 * (pageSpeedScore / 100)) * 100;

    // Hard rule: no first-party tracking cookies => cap overall to 50, and tank platform scores.
    if (fpTrackingCookies.length === 0) {
      if (overallScore > 50) {
        overallScore = 50;
        capsApplied.push(
          "No first-party tracking cookies: overall capped at 50.",
        );
      }
      for (const pr of platforms) {
        pr.score = Math.min(pr.score, 30);
        pr.signal = "None";
        pr.estimatedRevenueLoss = "High";
        pr.resolveCTA =
          "Implement first-party tracking cookies and route events through a first-party collector endpoint.";
      }
      notes.push(
        "Hard cap triggered: zero first-party tracking cookies found.",
      );
    }

    // Small platform-level cap: if platform has zero FP cookies, cap that platform
    for (const pr of platforms) {
      if (pr.debug.fpCookies.length === 0) {
        pr.score = Math.min(pr.score, 40);
      }
    }

    overallScore = Math.round(overallScore);

    const letterGrade = toLetterGrade(overallScore);

    const recommendedActions = buildRecommendedActions({
      fpTrackingCookies,
      routingSignal: routing.signal,
      vendorDirectPosts: routing.vendorDirectPosts,
      firstPartyRoutingPosts: routing.firstPartyRoutingPosts,
    });

    const hostBreakdown = summarizeHosts(combined, rootDomain);

    const result: AuditResult = {
      url,
      overallScore,
      letterGrade,
      signal: routing.signal,
      recommendedActions,
      platforms,
      cookies: {
        all: allCookies,
        tracking: trackingCookies,
        firstPartyTracking: fpTrackingCookies,
        thirdPartyTracking: tpTrackingCookies,
      },
      evidence: {
        requests: reqEvidence,
      },
      debug: {
        notes,
        loadMs: combined.loadMs,
        pageSpeedScore,
        trackingScore,
        capsApplied,
        totals: {
          cookiesSeen: allCookies.length,
          trackingCookiesSeen: trackingCookies.length,
          fpTrackingCookies: fpTrackingCookies.length,
          tpTrackingCookies: tpTrackingCookies.length,
          fpRoutingPosts: routing.firstPartyRoutingPosts,
          vendorDirectPosts: routing.vendorDirectPosts,
        },
        hostBreakdown,
      },
    };

    return result;
  } finally {
    await browser.close();
  }
}

// -----------------------------
// Capture
// -----------------------------
type CaptureBundle = {
  loadMs: number;
  setCookieHeaders: string[];
  requests: Array<{
    url: string;
    method: string;
    hostname: string;
    status?: number;
    requestHeaders?: Record<string, string>;
    responseHeaders?: Record<string, string>;
    postData?: string | null;
    resourceType?: string;
  }>;
};

async function capturePass(
  browser: Browser,
  url: string,
  timeoutMs: number,
  notes: string[],
  isSecondPass = false,
): Promise<CaptureBundle> {
  const context = await browser.newContext();
  const page = await context.newPage();

  const setCookieHeaders: string[] = [];
  const reqs: CaptureBundle["requests"] = [];

  page.on("request", async (r: Request) => {
    const u = safeUrl(r.url());
    if (!u) return;

    const hostname = u.hostname;
    let postData: string | null = null;
    try {
      postData = r.postData();
    } catch {
      postData = null;
    }

    reqs.push({
      url: r.url(),
      method: r.method(),
      hostname,
      requestHeaders: lowerKeys(await r.allHeaders().catch(() => ({}) as any)),
      postData,
      resourceType: r.resourceType(),
    });
  });

  page.on("response", async (resp: Response) => {
    const headers = await resp.allHeaders().catch(() => ({}) as any);
    const sc = headers["set-cookie"];
    if (sc) {
      if (Array.isArray(sc)) setCookieHeaders.push(...sc);
      else setCookieHeaders.push(sc);
    }

    // attach response info to last matching request (best-effort)
    const r = resp.request();
    const last = [...reqs]
      .reverse()
      .find((x) => x.url === r.url() && x.method === r.method());
    if (last) {
      last.status = resp.status();
      last.responseHeaders = lowerKeys(headers as any);
    }
  });

  const start = Date.now();
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: timeoutMs });
    // Light settle: let late scripts fire
    await page.waitForTimeout(1500);
  } catch (e: any) {
    notes.push(
      `${isSecondPass ? "Pass 2" : "Pass 1"} navigation error: ${String(e?.message ?? e)}`,
    );
  }
  const loadMs = Date.now() - start;

  // Minimal “user-ish” interaction to trigger some trackers
  try {
    await page.mouse.wheel(0, 800);
    await page.waitForTimeout(750);
  } catch {
    // ignore
  }

  await page.close().catch(() => {});
  await context.close().catch(() => {});

  if (isSecondPass) notes.push("Ran second pass with synthetic click IDs.");

  return { loadMs, setCookieHeaders, requests: reqs };
}

function mergeCaptureBundles(
  a: CaptureBundle,
  b: CaptureBundle | null,
): CaptureBundle {
  if (!b) return a;
  return {
    loadMs: Math.max(a.loadMs, b.loadMs),
    setCookieHeaders: dedupe([...a.setCookieHeaders, ...b.setCookieHeaders]),
    requests: dedupeByKey(
      [...a.requests, ...b.requests],
      (r) => `${r.method} ${r.url} ${r.postData ?? ""}`,
    ),
  };
}

// -----------------------------
// Cookie parsing + classification
// -----------------------------
function parseAndClassifyCookies(
  setCookieHeaders: string[],
  rootDomain: string | null,
): CookieRecord[] {
  const cookies: CookieRecord[] = [];

  for (const raw of setCookieHeaders) {
    const parsed = parseSetCookie(raw);
    if (!parsed) continue;

    const name = parsed.name;
    const domain = normalizeCookieDomain(parsed.domain) ?? ""; // may be empty

    const hostType = classifyHostType(domain || rootDomain || "", rootDomain);

    const catalogHit = COOKIE_CATALOG.find((e) => e.match(name));
    const inferred = inferProviderFromName(name);

    const provider = (catalogHit?.provider ?? inferred.provider) as Platform;
    const category = (catalogHit?.category ?? inferred.category) as Category;

    const lifetimeDays =
      computeLifetimeDays(parsed.maxAge, parsed.expires) ??
      catalogHit?.defaultLifetimeDays ??
      null;

    const isTracking = Boolean(catalogHit) || isKnownIdentifierCookieName(name);

    const isFirstPartyTracking =
      isTracking && (hostType === "root" || hostType === "firstPartySubdomain");
    const isThirdPartyTracking = isTracking && hostType === "thirdParty";

    cookies.push({
      name,
      valuePreview: parsed.value ? previewValue(parsed.value) : undefined,
      domain: domain || "(not-set)",
      path: parsed.path,
      secure: parsed.secure,
      httpOnly: parsed.httpOnly,
      sameSite: parsed.sameSite,
      maxAge: parsed.maxAge,
      expires: parsed.expires,
      lifetimeDays,
      provider,
      category,
      hostType,
      isTracking,
      isFirstPartyTracking,
      isThirdPartyTracking,
    });
  }

  // Deduplicate by (name|domain|path)
  return dedupeByKey(cookies, (c) => `${c.name}|${c.domain}|${c.path ?? "/"}`);
}

function parseSetCookie(header: string): {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  maxAge?: number | null;
  expires?: string | null;
} | null {
  // Simple, robust-enough parser for scanner purposes.
  const parts = header.split(";").map((p) => p.trim());
  const [nv, ...attrs] = parts;
  if (!nv || !nv.includes("=")) return null;

  const eq = nv.indexOf("=");
  const name = nv.slice(0, eq).trim();
  const value = nv.slice(eq + 1).trim();

  let domain: string | undefined;
  let path: string | undefined;
  let secure = false;
  let httpOnly = false;
  let sameSite: string | undefined;
  let maxAge: number | null = null;
  let expires: string | null = null;

  for (const a of attrs) {
    const [kRaw, ...vRest] = a.split("=");
    const k = (kRaw ?? "").trim().toLowerCase();
    const v = vRest.join("=").trim();

    if (k === "domain") domain = v;
    else if (k === "path") path = v;
    else if (k === "secure") secure = true;
    else if (k === "httponly") httpOnly = true;
    else if (k === "samesite") sameSite = v;
    else if (k === "max-age") {
      const n = Number(v);
      maxAge = Number.isFinite(n) ? n : null;
    } else if (k === "expires") {
      expires = v || null;
    }
  }

  return {
    name,
    value,
    domain,
    path,
    secure,
    httpOnly,
    sameSite,
    maxAge,
    expires,
  };
}

function normalizeCookieDomain(domain?: string): string | null {
  if (!domain) return null;
  const d = domain.trim().toLowerCase();
  if (!d) return null;
  return d.startsWith(".") ? d.slice(1) : d;
}

function computeLifetimeDays(
  maxAge: number | null | undefined,
  expires: string | null | undefined,
): number | null {
  if (typeof maxAge === "number" && Number.isFinite(maxAge)) {
    if (maxAge <= 0) return 0;
    return Math.round((maxAge / 86400) * 10) / 10;
  }
  if (expires) {
    const t = Date.parse(expires);
    if (!Number.isNaN(t)) {
      const ms = t - Date.now();
      return Math.round((ms / (86400 * 1000)) * 10) / 10;
    }
  }
  return null;
}

function classifyHostType(
  cookieDomainOrHost: string,
  rootDomain: string | null,
): HostType {
  const d = cookieDomainOrHost.toLowerCase();
  if (!rootDomain) return "thirdParty";
  if (d === rootDomain) return "root";
  if (d.endsWith(`.${rootDomain}`)) return "firstPartySubdomain";
  return "thirdParty";
}

function inferProviderFromName(name: string): {
  provider: Platform;
  category: Category;
} {
  const n = name.toLowerCase();

  if (n === "_fbp" || n === "_fbc")
    return { provider: "Meta", category: "Ads" };
  if (n === "_ttp") return { provider: "TikTok", category: "Ads" };
  if (n === "_gcl_au") return { provider: "Google Ads", category: "Ads" };
  if (n === "_ga" || n.startsWith("_ga_"))
    return { provider: "Google Analytics", category: "Analytics" };

  return { provider: "Unknown", category: "Analytics" };
}

function isKnownIdentifierCookieName(name: string): boolean {
  const n = name.toLowerCase();
  return (
    n === "_ga" ||
    n.startsWith("_ga_") ||
    n === "_fbp" ||
    n === "_fbc" ||
    n === "_gcl_au" ||
    n === "_ttp"
  );
}

// -----------------------------
// Request evidence + routing inference
// -----------------------------
function buildRequestEvidence(
  requests: CaptureBundle["requests"],
  rootDomain: string | null,
): RequestEvidence[] {
  const evidences: RequestEvidence[] = [];

  for (const r of requests) {
    const u = safeUrl(r.url);
    if (!u) continue;

    const hostname = u.hostname.toLowerCase();
    const hostType = classifyHostType(hostname, rootDomain);

    const method = r.method.toUpperCase();
    const isPost = method === "POST";

    const contentType =
      r.requestHeaders?.["content-type"] ||
      r.responseHeaders?.["content-type"] ||
      undefined;

    const post = r.postData ?? "";
    const query = u.searchParams.toString();

    const hay = `${u.pathname}?${query}\n${post}`.toLowerCase();

    const containsIdentifiers = {
      gclid: containsAny(hay, IDENTIFIER_KEYS.gclid),
      fbclid: containsAny(hay, IDENTIFIER_KEYS.fbclid),
      fbp: containsAny(hay, IDENTIFIER_KEYS.fbp),
      fbc: containsAny(hay, IDENTIFIER_KEYS.fbc),
      gaClient: containsAny(hay, IDENTIFIER_KEYS.gaClient),
      ttp: containsAny(hay, IDENTIFIER_KEYS.ttp),
      genericId: /(^|[^a-z])(id|clientid|userid|sessionid|sid)([^a-z]|$)/i.test(
        hay,
      ),
    };

    const platformDirect: RequestEvidence["platformDirect"] = {};
    for (const m of VENDOR_HOST_MATCHERS) {
      if (m.match(hostname)) platformDirect[m.platform] = true;
    }

    evidences.push({
      url: r.url,
      method,
      hostname,
      hostType,
      isPost,
      contentType,
      postBodyBytes: post ? Buffer.byteLength(post, "utf8") : 0,
      containsIdentifiers,
      platformDirect,
    });
  }

  return evidences;
}

function evaluateRouting(evidence: RequestEvidence[]): {
  signal: SignalStrength;
  firstPartyRoutingPosts: number;
  vendorDirectPosts: number;
} {
  let fpPostsWithIds = 0;
  let fpPostsAny = 0;
  let vendorDirectPosts = 0;

  for (const e of evidence) {
    if (!e.isPost) continue;

    const isVendor = Object.values(e.platformDirect).some(Boolean);
    if (isVendor) vendorDirectPosts += 1;

    if (e.hostType === "root" || e.hostType === "firstPartySubdomain") {
      fpPostsAny += 1;
      if (
        e.containsIdentifiers.gclid ||
        e.containsIdentifiers.fbclid ||
        e.containsIdentifiers.fbp ||
        e.containsIdentifiers.fbc ||
        e.containsIdentifiers.gaClient ||
        e.containsIdentifiers.ttp ||
        e.containsIdentifiers.genericId
      ) {
        fpPostsWithIds += 1;
      }
    }
  }

  // Strong: first-party POST(s) with identifiers
  if (fpPostsWithIds >= 1) {
    return {
      signal: "Strong",
      firstPartyRoutingPosts: fpPostsWithIds,
      vendorDirectPosts,
    };
  }

  // Weak: first-party POST(s) exist, but unclear identifiers OR only a small amount
  if (fpPostsAny >= 1) {
    return {
      signal: "Weak",
      firstPartyRoutingPosts: fpPostsAny,
      vendorDirectPosts,
    };
  }

  // None: no identifiable tracking POSTs to first-party endpoints
  return { signal: "None", firstPartyRoutingPosts: 0, vendorDirectPosts };
}

// -----------------------------
// Scoring
// -----------------------------
function scorePageSpeed(loadMs: number): number {
  // Only penalize if bad. Otherwise mostly ignored.
  // 0-100 where <4s ~ 100, 8s ~ 70, 12s ~ 40, 20s ~ 10
  if (!Number.isFinite(loadMs) || loadMs <= 0) return 80;

  const s = loadMs / 1000;
  if (s <= 4) return 100;
  if (s <= 8) return Math.round(100 - (s - 4) * 7.5); // down to ~70
  if (s <= 12) return Math.round(70 - (s - 8) * 7.5); // down to ~40
  if (s <= 20) return Math.round(40 - (s - 12) * 3.75); // down to ~10
  return 5;
}

function scoreTracking(
  trackingCookies: CookieRecord[],
  fpTrackingCookies: CookieRecord[],
  routing: {
    signal: SignalStrength;
    firstPartyRoutingPosts: number;
    vendorDirectPosts: number;
  },
): number {
  // Cookies dominate.
  // Third-party cookies: score-neutral (tracked but do not add or subtract).
  // Routing: big win if FP POSTs with IDs; penalty if no FP routing posts at all (because SST inference absent).

  // If no tracking cookies at all: very low.
  if (trackingCookies.length === 0) {
    // still allow a small score (maybe scripts blocked) but basically failing.
    return 10;
  }

  // Cookie quality score: based on *presence and quality* of FP tracking cookies only.
  // - Count/coverage matters.
  // - Lifetime matters.
  // - Secure/HttpOnly are minor boosts.
  let cookieScore = 0;

  // Coverage: diminishing returns; 1 good FP cookie is meaningful.
  const fpCount = fpTrackingCookies.length;
  const coverage = clamp01(fpCount / 4); // 0..1 with saturation at 4 FP tracking cookies
  cookieScore += coverage * 55;

  // Lifetime: average normalized; null treated as mediocre.
  const lifetimeNorms = fpTrackingCookies.map((c) =>
    lifetimeToNorm(c.lifetimeDays),
  );
  const avgLifetime = lifetimeNorms.length
    ? lifetimeNorms.reduce((a, b) => a + b, 0) / lifetimeNorms.length
    : 0;
  cookieScore += avgLifetime * 30;

  // Flags: small boost
  const secureRatio = fpTrackingCookies.length
    ? fpTrackingCookies.filter((c) => c.secure).length /
      fpTrackingCookies.length
    : 0;
  const httpOnlyRatio = fpTrackingCookies.length
    ? fpTrackingCookies.filter((c) => c.httpOnly).length /
      fpTrackingCookies.length
    : 0;
  cookieScore += secureRatio * 5 + httpOnlyRatio * 5;

  // Routing score: inferred SST signal.
  let routingScore = 0;
  if (routing.signal === "Strong") routingScore = 100;
  else if (routing.signal === "Weak") routingScore = 55;
  else routingScore = 10; // penalty for no FP routing evidence

  // Blend: cookies (75%) + routing (25%) inside trackingScore bucket
  const tracking = 0.75 * (cookieScore / 100) + 0.25 * (routingScore / 100);
  return Math.round(clamp01(tracking) * 100);
}

function scorePlatform(
  platform: Exclude<Platform, "Unknown">,
  trackingCookies: CookieRecord[],
  evidence: RequestEvidence[],
  overallFpRoutingPosts: number,
): PlatformReport {
  const platformCookies = trackingCookies.filter(
    (c) => c.provider === platform,
  );
  const fpCookies = platformCookies.filter((c) => c.isFirstPartyTracking);
  const tpCookies = platformCookies.filter((c) => c.isThirdPartyTracking);

  // Detect direct-to-vendor POSTs
  const directVendorPosts = evidence.some(
    (e) => e.isPost && e.platformDirect?.[platform] === true,
  );

  // FP routing posts "attributed" to platform: look for IDs relevant to that platform inside FP POSTs
  const fpPostsForPlatform = evidence.filter((e) => {
    if (!e.isPost) return false;
    if (!(e.hostType === "root" || e.hostType === "firstPartySubdomain"))
      return false;

    if (platform === "Meta")
      return (
        e.containsIdentifiers.fbclid ||
        e.containsIdentifiers.fbp ||
        e.containsIdentifiers.fbc
      );
    if (platform === "Google Analytics") return e.containsIdentifiers.gaClient;
    if (platform === "Google Ads") return e.containsIdentifiers.gclid;
    if (platform === "TikTok") return e.containsIdentifiers.ttp;
    return false;
  });

  // Signal strength per platform
  let signal: SignalStrength = "None";
  if (fpPostsForPlatform.length >= 1) signal = "Strong";
  else if (overallFpRoutingPosts >= 1) signal = "Weak";

  // Score: FP cookies + lifetime + routing
  let score = 0;

  // FP cookie presence (dominant)
  if (fpCookies.length === 0) score += 5;
  else score += Math.min(60, 25 + fpCookies.length * 12);

  // Lifetime quality
  const lifetimeNorms = fpCookies.map((c) => lifetimeToNorm(c.lifetimeDays));
  const avgLifetime = lifetimeNorms.length
    ? lifetimeNorms.reduce((a, b) => a + b, 0) / lifetimeNorms.length
    : 0;
  score += avgLifetime * 25;

  // Routing signal
  if (signal === "Strong") score += 15;
  else if (signal === "Weak") score += 7;
  else score += 0;

  // Direct vendor traffic is neutral (no penalty, no reward) per your rules.
  // But if there's *only* vendor direct and no FP cookies, that should feel bad already.

  score = Math.round(clamp01(score / 100) * 100);

  const estimatedRevenueLoss = estimateRevenueLoss(score, signal);

  const resolveCTA = buildPlatformCTA(platform, fpCookies.length, signal);

  return {
    platform,
    score,
    signal,
    estimatedRevenueLoss,
    resolveCTA,
    debug: {
      fpCookies: fpCookies.map((c) => c.name),
      tpCookies: tpCookies.map((c) => c.name),
      fpRoutingPosts: fpPostsForPlatform.length,
      directToVendors: directVendorPosts,
    },
  };
}

function lifetimeToNorm(days: number | null): number {
  // Normalize to 0..1
  // - null: 0.55 (unknown is mediocre)
  // - 0..7: poor
  // - 30: decent
  // - 90: good
  // - 365+: great
  if (days === null) return 0.55;
  if (days <= 0) return 0;
  if (days < 7) return 0.15;
  if (days < 30) return 0.35;
  if (days < 90) return 0.6;
  if (days < 180) return 0.75;
  if (days < 365) return 0.9;
  return 1.0;
}

// -----------------------------
// Recommended actions + grade
// -----------------------------
function buildRecommendedActions(input: {
  fpTrackingCookies: CookieRecord[];
  routingSignal: SignalStrength;
  vendorDirectPosts: number;
  firstPartyRoutingPosts: number;
}): string {
  const { fpTrackingCookies, routingSignal, firstPartyRoutingPosts } = input;

  if (fpTrackingCookies.length === 0) {
    return [
      "Your site is not setting any first-party tracking cookies, so it cannot preserve attribution reliably.",
      "Start by implementing first-party versions of key platform cookies (e.g. _ga, _fbp/_fbc) on the root domain or a first-party tracking subdomain, then route collection through a first-party endpoint.",
    ].join(" ");
  }

  if (routingSignal === "None") {
    return [
      "You have first-party tracking cookies, but we did not observe any first-party routed collection POSTs.",
      "Add a first-party collector endpoint (root domain or tracking subdomain) that receives analytics-style POSTs and forwards server-side, preserving identifiers end-to-end.",
    ].join(" ");
  }

  if (routingSignal === "Weak") {
    return [
      "We observed some first-party routed collection, but identifier preservation is unclear.",
      "Ensure your first-party collector POST payloads include click IDs and client IDs (gclid/fbclid/_ga/_fbp) so attribution survives browser restrictions.",
    ].join(" ");
  }

  // Strong
  if (firstPartyRoutingPosts >= 3) {
    return "Strong first-party routed collection detected with identifiers. Next step: validate event coverage (purchase/lead), dedupe rules, and server-side matching quality per platform.";
  }

  return "First-party routed collection detected with identifiers. Expand coverage across key user flows (landing → conversion) and verify identifier continuity to maximize match rates.";
}

function toLetterGrade(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function estimateRevenueLoss(
  score: number,
  signal: SignalStrength,
): "Low" | "Medium" | "High" {
  if (score >= 80 && signal === "Strong") return "Low";
  if (score >= 55) return "Medium";
  return "High";
}

function buildPlatformCTA(
  platform: Exclude<Platform, "Unknown">,
  fpCookieCount: number,
  signal: SignalStrength,
): string {
  if (fpCookieCount === 0) {
    return `Add first-party ${platform} cookies and validate they are set on the root domain or a first-party tracking subdomain.`;
  }
  if (signal === "None") {
    return `Route ${platform} collection through a first-party endpoint and include the platform identifiers in the POST payload.`;
  }
  if (signal === "Weak") {
    return `Ensure ${platform} identifiers are preserved end-to-end in your first-party collector payloads.`;
  }
  return `Maintain ${platform} server-side routing and expand coverage to key conversion events.`;
}

// -----------------------------
// Utilities
// -----------------------------
function getRootDomain(url: string): string | null {
  const u = safeUrl(url);
  if (!u) return null;
  const parsed = parseTld(u.hostname);
  if (!parsed?.domain) return null;
  return parsed.domain.toLowerCase();
}

function addSyntheticClickIds(url: string): string {
  const u = safeUrl(url);
  if (!u) return url;

  // Common “exposure” trick: add click IDs
  u.searchParams.set("gclid", "test-gclid-123");
  u.searchParams.set("fbclid", "test-fbclid-123");
  // you can add more if you want
  return u.toString();
}

function safeUrl(s: string): URL | null {
  try {
    return new URL(s);
  } catch {
    return null;
  }
}

function lowerKeys(obj: Record<string, any>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj ?? {})) {
    if (typeof v === "string") out[k.toLowerCase()] = v;
  }
  return out;
}

function containsAny(haystackLower: string, needles: string[]): boolean {
  for (const n of needles) {
    if (haystackLower.includes(n.toLowerCase())) return true;
  }
  return false;
}

function clamp01(x: number): number {
  if (x < 0) return 0;
  if (x > 1) return 1;
  return x;
}

function dedupe<T>(arr: T[]): T[] {
  return Array.from(new Set(arr));
}

function dedupeByKey<T>(arr: T[], keyFn: (t: T) => string): T[] {
  const m = new Map<string, T>();
  for (const item of arr) m.set(keyFn(item), item);
  return [...m.values()];
}

function previewValue(v: string): string {
  if (v.length <= 24) return v;
  return `${v.slice(0, 10)}…${v.slice(-6)}`;
}

// -----------------------------
// Host breakdown (debug trust)
// -----------------------------
function summarizeHosts(combined: CaptureBundle, rootDomain: string | null) {
  const map = new Map<
    string,
    {
      hostname: string;
      hostType: HostType;
      requests: number;
      posts: number;
      setCookieResponses: number;
      cookieNames: Record<string, number>;
    }
  >();

  for (const r of combined.requests) {
    const h = (r.hostname ?? "").toLowerCase();
    if (!h) continue;

    const hostType = classifyHostType(h, rootDomain);

    const key = h;
    if (!map.has(key)) {
      map.set(key, {
        hostname: h,
        hostType,
        requests: 0,
        posts: 0,
        setCookieResponses: 0,
        cookieNames: {},
      });
    }
    const row = map.get(key)!;
    row.requests += 1;
    if (r.method?.toUpperCase() === "POST") row.posts += 1;

    // best-effort: if this response had set-cookie, count it (we don't have perfect mapping here)
    if (r.responseHeaders?.["set-cookie"]) row.setCookieResponses += 1;
  }

  // Attach cookie names by domain (rough but useful)
  // If cookie domain matches hostname exactly, count it.
  // (You’ll still have full cookie list elsewhere.)
  // NOTE: This is debug-only.
  return [...map.values()]
    .map((x) => {
      return x;
    })
    .sort((a, b) => b.requests - a.requests)
    .slice(0, 25);
}
