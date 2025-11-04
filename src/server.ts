import Fastify from "fastify";
import { z } from "zod";
import { runAudit } from "./audit.js";

const app = Fastify({ logger: true });

// --- Basic Auth (optional security) ---
app.addHook("preHandler", async (req, reply) => {
  const auth = req.headers.authorization || "";
  const expected =
    "Basic " +
    Buffer.from(`admin:${process.env.AUDIT_KEY || "secret"}`).toString("base64");

  if (req.url === "/") return; // skip health check
  if (auth !== expected) {
    reply.code(401).header("WWW-Authenticate", "Basic").send({ error: "Unauthorized" });
  }
});

// --- Routes ---
app.get("/", async () => ({ ok: true, name: "tracking-audit-full-v2" }));

app.post("/audit", async (req, reply) => {
  const Body = z.object({ url: z.string().url() });
  const parsed = Body.safeParse(req.body);
  if (!parsed.success) return reply.code(400).send({ error: "invalid body" });

  try {
    const report = await runAudit(parsed.data.url);
    return report;
  } catch (err: any) {
    req.log.error(err);
    reply.code(500).send({ error: "audit failed", message: err.message });
  }
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
