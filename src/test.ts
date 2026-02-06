import { runAudit } from "./audit.js";

type ServerLikeResponse<T> = {
  id: string;
  url: string;
  status: "queued" | "running" | "finished" | "failed";
  progress: number;
  result: T | null;
  error: string | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
};

function nowIso() {
  return new Date().toISOString();
}

function makeId() {
  return `local_${Math.random().toString(16).slice(2)}_${Date.now()}`;
}

async function main() {
  const url = process.argv[2];

  if (!url) {
    console.log("Usage: npm run test https://example.com");
    process.exit(1);
  }

  const job: ServerLikeResponse<Awaited<ReturnType<typeof runAudit>>> = {
    id: makeId(),
    url,
    status: "queued",
    progress: 0,
    result: null,
    error: null,
    createdAt: nowIso(),
    startedAt: null,
    finishedAt: null,
  };

  // mimic server lifecycle
  console.log("Running audit on:", url);
  console.log("--------------------------------------------------");

  job.status = "running";
  job.progress = 25;
  job.startedAt = nowIso();

  try {
    const result = await runAudit(url, {
      headless: false, // 👈 see browser while testing
      twoPass: true,
      syntheticClickIds: true,
    });

    job.status = "finished";
    job.progress = 100;
    job.result = result;
    job.finishedAt = nowIso();

    // Keep your existing human-friendly sections too (optional)
    // console.log("\n========== DEBUG NOTES ==========");
    // console.log(result.debug.notes);

    // console.log("\n========== ROOT DOMAIN COOKIES ==========");
    // const rootCookies = result.cookies.all.filter((c) => c.hostType === "root");
    // console.log(JSON.stringify(rootCookies, null, 2));

    // console.log("\n========== WATCHED SUBDOMAIN → ROOT COOKIE SETS ==========");
    // console.log(
    //   JSON.stringify(result.signals.watchedSubdomainRootCookieSets, null, 2),
    // );
    // Print the full “server-like” payload first (this is what your frontend/server would return)
    console.log("\n========== SERVER RESPONSE (LOCAL MOCK) ==========");
    console.log(JSON.stringify(job, null, 2));
  } catch (err: any) {
    job.status = "failed";
    job.progress = 100;
    job.error = String(err?.message ?? err);
    job.finishedAt = nowIso();

    console.log("\n========== SERVER RESPONSE (LOCAL MOCK) ==========");
    console.log(JSON.stringify(job, null, 2));

    console.error("Audit failed:", err);
    process.exitCode = 1;
  }
}

main();
