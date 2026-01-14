import "dotenv/config";
import pg from "pg";
import { runAudit } from "./audit.js";

const { Pool } = pg;

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) throw new Error("Missing DATABASE_URL env var");

const POLL_MS = Number(process.env.WORKER_POLL_MS || 2000);

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

type AuditRow = {
  id: string;
  url: string;
};

async function sleep(ms: number) {
  return new Promise((res) => setTimeout(res, ms));
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
  console.log(`Worker started. Polling every ${POLL_MS}ms`);

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

      const report = await runAudit(job.url);

      console.log(`Finished audit ${job.id}`);
      await markFinished(job.id, report);
    } catch (err: any) {
      console.error("Worker loop error:", err?.message || err);
      if (job) {
        await markFailed(job.id, err?.message || "Unknown audit error");
      }
    }
  }
}

main().catch((e) => {
  console.error("Fatal worker error:", e);
  process.exit(1);
});
