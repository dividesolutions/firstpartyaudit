import "dotenv/config";
import pg from "pg";
import { runAudit } from "./audit.js";

const { Pool } = pg;

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) throw new Error("Missing DATABASE_URL env var");

const POLL_MS = Number(process.env.WORKER_POLL_MS || 2000);
const AUDIT_TIMEOUT_MS = Number(process.env.AUDIT_TIMEOUT_MS || 120000); // 2 min default

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

type AuditRow = {
  id: string;
  url: string;
};

const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms));

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(
      () => reject(new Error(`Audit timed out after ${ms}ms`)),
      ms
    );
    p.then((v) => {
      clearTimeout(t);
      resolve(v);
    }).catch((e) => {
      clearTimeout(t);
      reject(e);
    });
  });
}

/**
 * Atomically claims one queued job.
 * Uses FOR UPDATE SKIP LOCKED so multiple workers won't grab the same row.
 */
async function claimNextQueued(): Promise<AuditRow | null> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const sel = await client.query(
      `
      SELECT id, url
      FROM audits
      WHERE status = 'queued'
      ORDER BY created_at ASC
      FOR UPDATE SKIP LOCKED
      LIMIT 1
      `
    );

    if (sel.rowCount === 0) {
      await client.query("COMMIT");
      return null;
    }

    const job = sel.rows[0] as AuditRow;

    await client.query(
      `
      UPDATE audits
      SET status = 'running',
          progress = 5,
          started_at = NOW(),
          updated_at = NOW(),
          error = NULL
      WHERE id = $1
      `,
      [job.id]
    );

    await client.query("COMMIT");
    return job;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

async function markFinished(id: string, result: any) {
  await pool.query(
    `
    UPDATE audits
    SET status = 'finished',
        progress = 100,
        result_json = $2::jsonb,
        finished_at = NOW(),
        updated_at = NOW()
    WHERE id = $1
    `,
    [id, JSON.stringify(result)]
  );
}

async function markFailed(id: string, message: string) {
  await pool.query(
    `
    UPDATE audits
    SET status = 'failed',
        error = $2,
        finished_at = NOW(),
        updated_at = NOW()
    WHERE id = $1
    `,
    [id, message]
  );
}

async function main() {
  await requeueStaleRunning();
  console.log(
    `Worker started. Polling every ${POLL_MS}ms. Timeout ${AUDIT_TIMEOUT_MS}ms`
  );

  while (true) {
    let job: AuditRow | null = null;

    try {
      job = await claimNextQueued();

      if (!job) {
        await sleep(POLL_MS);
        continue;
      }

      console.log(`Running audit ${job.id} for ${job.url}`);

      // Optional: bump progress a bit
      await pool.query(
        `UPDATE audits SET progress = 25, updated_at = NOW() WHERE id = $1`,
        [job.id]
      );

      const report = await withTimeout(runAudit(job.url), AUDIT_TIMEOUT_MS);

      console.log(`Finished audit ${job.id}`);
      await markFinished(job.id, report);
    } catch (err: any) {
      console.error("Worker loop error:", err?.message || err);

      if (job) {
        await markFailed(job.id, err?.message || "Unknown audit error");
      }

      // Prevent tight loop on repeated errors (DB down, etc.)
      await sleep(POLL_MS);
    }
  }
}

async function requeueStaleRunning() {
  const minutes = Number(process.env.STALE_MINUTES || 15);
  const res = await pool.query(
    `
    UPDATE audits
    SET status = 'queued',
        progress = 0,
        updated_at = NOW(),
        error = 'Re-queued (stale running job)'
    WHERE status = 'running'
      AND started_at < NOW() - ($1 || ' minutes')::interval
    `,
    [minutes]
  );

  if (res.rowCount) {
    console.log(`Re-queued ${res.rowCount} stale running job(s)`);
  }
}

process.on("SIGTERM", async () => {
  console.log("SIGTERM received, shutting down...");
  await pool.end();
  process.exit(0);
});
process.on("SIGINT", async () => {
  console.log("SIGINT received, shutting down...");
  await pool.end();
  process.exit(0);
});

main().catch((e) => {
  console.error("Fatal worker error:", e);
  process.exit(1);
});
