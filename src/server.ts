import "dotenv/config";
import Fastify from "fastify";
import type { FastifyReply, FastifyRequest } from "fastify";
import cors from "@fastify/cors";
import { createClient } from "@supabase/supabase-js";
import { z } from "zod";

const app = Fastify({ logger: true });

// ===== Env =====
const PORT = Number(process.env.PORT || 3001);
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error("Missing env: SUPABASE_URL and/or SUPABASE_SERVICE_ROLE_KEY");
}

// ===== Supabase Admin (server-side only) =====
const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ===== Helpers =====
type AuthedRequest = FastifyRequest & { user?: { id: string } };

async function requireUser(request: AuthedRequest, reply: FastifyReply) {
  const auth = request.headers.authorization;
  if (!auth?.startsWith("Bearer ")) {
    return reply.code(401).send({ error: "Missing Bearer token" });
  }

  const token = auth.slice("Bearer ".length);
  const { data, error } = await supabaseAdmin.auth.getUser(token);

  if (error || !data?.user) {
    return reply.code(401).send({ error: "Invalid token" });
  }

  request.user = { id: data.user.id };
}

// ===== Routes =====
app.get("/v1/health", async () => ({ ok: true }));

app.post("/v1/auth/login", async (request: FastifyRequest, reply: FastifyReply) => {
  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
  });

  const parsed = schema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({ error: "Invalid body", details: parsed.error.flatten() });
  }

  const { email, password } = parsed.data;

  // 🔥 usa o Auth do Supabase pra devolver access_token pro front
  const { data, error } = await supabaseAdmin.auth.signInWithPassword({ email, password });

  if (error || !data.session) {
    return reply.code(401).send({ error: "Invalid login credentials" });
  }

  return {
    access_token: data.session.access_token,
    refresh_token: data.session.refresh_token,
    user: { id: data.user?.id, email: data.user?.email },
  };
});

app.get(
  "/v1/analyses",
  { preHandler: requireUser },
  async (request: AuthedRequest, reply: FastifyReply) => {
    const userId = request.user!.id;

    const { data, error } = await supabaseAdmin
      .from("user_analyses")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false });

    if (error) return reply.code(500).send({ error: error.message });
    return { data };
  }
);

app.post(
  "/v1/analyses",
  { preHandler: requireUser },
  async (request: AuthedRequest, reply: FastifyReply) => {
    const schema = z.object({
      marketplace: z.string().min(1),
      file_name: z.string().min(1),
      analysis_data: z.any().optional(),
      summary: z.any().optional(),
    });

    const parsed = schema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({
        error: "Invalid body",
        details: parsed.error.flatten(),
      });
    }

    const userId = request.user!.id;
    const body = parsed.data;

    const { data, error } = await supabaseAdmin
      .from("user_analyses")
      .insert({
        user_id: userId,
        marketplace: body.marketplace,
        file_name: body.file_name,
        analysis_data: body.analysis_data ?? null,
        summary: body.summary ?? null,
        data_size_bytes: JSON.stringify(body.analysis_data ?? {}).length,
      })
      .select("*")
      .single();

    if (error) return reply.code(500).send({ error: error.message });
    return { data };
  }
);

// ===== Boot =====
async function main() {
  // CORS: libera localhost (dev) + Vercel + seu domínio (prod/homolog)
  await app.register(cors, {
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // curl/postman

      const allowed = [
        /^http:\/\/localhost:\d+$/,
        /^https:\/\/.*\.vercel\.app$/,
        /^https:\/\/(.*\.)?wcontrol\.app\.br$/,
      ];

      const ok = allowed.some((re) => re.test(origin));
      cb(null, ok);
    },
    credentials: true,
  });

  await app.listen({ port: PORT, host: "0.0.0.0" });
  app.log.info(`🚀 API rodando em http://localhost:${PORT}`);
}

main().catch((err) => {
  app.log.error(err);
  process.exit(1);
});