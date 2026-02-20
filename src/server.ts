import Fastify from "fastify";
import { z } from "zod";
import pg from "pg";
import "dotenv/config";
import cors from "@fastify/cors";

const { Pool } = pg;

const app = Fastify({ logger: true });

await app.register(cors, {
  origin: ["https://track.gofirstparty.com", "http://localhost:5173"],
  methods: ["GET", "POST", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  credentials: false, // set true only if you're using cookies
});

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) throw new Error("Missing DATABASE_URL env var");

const pool = new Pool({
  connectionString: DATABASE_URL,
  // Works for Render + local. If you ever need to disable, set PGSSLMODE=disable
  ssl: { rejectUnauthorized: false },
});

// --- Basic Auth (maybe use later) ---
// app.addHook("preHandler", async (req, reply) => {
//   const auth = req.headers.authorization || "";
//   const expected =
//     "Basic " +
//     Buffer.from(`admin:${process.env.AUDIT_KEY || "secret"}`).toString(
//       "base64"
//     );

//   if (req.url === "/") return; // health check
//   if (auth !== expected) {
//     return reply
//       .code(401)
//       .header("WWW-Authenticate", "Basic")
//       .send({ error: "Unauthorized" });
//   }
// });

// --- Routes ---
app.get("/", async () => ({ ok: true, name: "tracking-audit-api" }));

// Create job
app.post("/audits", async (req, reply) => {
  const Body = z.object({
    url: z.string().url(),
    email: z.string().email().optional().nullable(),
  });

  const parsed = Body.safeParse(req.body);
  if (!parsed.success) {
    return reply
      .code(400)
      .send({ error: "invalid body", issues: parsed.error.issues });
  }

  const { url, email } = parsed.data;

  const result = await pool.query(
    `
    INSERT INTO audits (url, email, status, progress)
    VALUES ($1, $2, 'queued', 0)
    RETURNING id
    `,
    [url, email ?? null],
  );

  return reply.code(201).send({ id: result.rows[0].id });
});

//Append email to job
app.patch("/audits/:id/email", async (req, reply) => {
  const id = (req.params as any).id as string;

  if (!/^[0-9a-fA-F-]{36}$/.test(id)) {
    return reply.code(400).send({ error: "invalid id" });
  }

  const Body = z.object({ email: z.string().email() });
  const parsed = Body.safeParse(req.body);
  if (!parsed.success) {
    return reply
      .code(400)
      .send({ error: "invalid body", issues: parsed.error.issues });
  }

  const result = await pool.query(
    `UPDATE audits SET email = $2, updated_at = NOW() WHERE id = $1 RETURNING id, email`,
    [id, parsed.data.email],
  );

  if (result.rowCount === 0)
    return reply.code(404).send({ error: "not found" });

  return { ok: true, id: result.rows[0].id, email: result.rows[0].email };
});

// Check status / results
app.get("/audits/:id", async (req, reply) => {
  const id = (req.params as any).id as string;

  // basic UUID format check
  if (!/^[0-9a-fA-F-]{36}$/.test(id)) {
    return reply.code(400).send({ error: "invalid id" });
  }

  const result = await pool.query(
    `
    SELECT id, url, email, status, progress, result_json, error, created_at, started_at, finished_at
    FROM audits
    WHERE id = $1
    `,
    [id],
  );

  if (result.rowCount === 0)
    return reply.code(404).send({ error: "not found" });

  const row = result.rows[0];
  return {
    id: row.id,
    url: row.url,
    email: row.email,
    status: row.status,
    progress: row.progress,
    result: row.result_json,
    error: row.error,
    createdAt: row.created_at,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
  };
});

// --- Startup ---
const port = Number(process.env.PORT || 3000);
app
  .listen({ port, host: "0.0.0.0" })
  .then(() => console.log(`🚀 Listening on ${port}`))
  .catch((err) => {
    console.error("Server failed to start:", err);
    process.exit(1);
  });
