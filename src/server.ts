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
type AuthedRequest = FastifyRequest & { user?: { id: string; email?: string } };

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

  request.user = { id: data.user.id, email: data.user.email ?? undefined };
}

// ===== Routes =====
app.get("/", async () => ({
  ok: true,
  service: "profit-clarity-api",
}));

app.get("/v1/health", async () => ({ ok: true }));

app.get("/v1/auth/me", { preHandler: requireUser }, async (request: AuthedRequest) => {
  return { user: request.user };
});

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

// ✅ CADASTRO (signup) - rota principal
app.post("/v1/auth/signup", async (request: FastifyRequest, reply: FastifyReply) => {
  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
    // se teu form manda mais coisas, a gente guarda no metadata
    name: z.string().min(1).optional(),
    phone: z.string().min(8).optional(),
    city: z.string().optional(),
    uf: z.string().optional(),
  });

  const parsed = schema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({ error: "Invalid body", details: parsed.error.flatten() });
  }

  const { email, password, ...rest } = parsed.data;

  // 1) Cria usuário via Admin
  const { data: created, error: createErr } = await supabaseAdmin.auth.admin.createUser({
    email,
    password,
    email_confirm: true, // 👈 deixa entrar direto na homolog (se quiser exigir email, troca pra false)
    user_metadata: rest,
  });

  if (createErr) {
    // email já existe, etc.
    return reply.code(400).send({ error: createErr.message });
  }

  // 2) Auto-login (gera access_token pro front)
  const { data: sessionData, error: loginErr } = await supabaseAdmin.auth.signInWithPassword({
    email,
    password,
  });

  if (loginErr || !sessionData.session) {
    // Usuário criado mas login falhou (raro). Devolve user e pede login manual.
    return reply.code(201).send({
      user: { id: created.user?.id, email: created.user?.email },
      warning: "User created but auto-login failed. Please login.",
    });
  }

  return reply.code(201).send({
    access_token: sessionData.session.access_token,
    refresh_token: sessionData.session.refresh_token,
    user: { id: sessionData.user?.id, email: sessionData.user?.email },
  });
});

// ✅ ALIAS (caso teu front use /register)
app.post("/v1/auth/register", async (request: FastifyRequest, reply: FastifyReply) => {
  // reusa exatamente a mesma lógica do signup
  return app.inject({
    method: "POST",
    url: "/v1/auth/signup",
    payload: request.body as any,
    headers: request.headers as any,
  }).then((res) => {
    reply.code(res.statusCode).headers(res.headers).send(res.json());
  });
});

app.get("/v1/analyses", { preHandler: requireUser }, async (request: AuthedRequest, reply: FastifyReply) => {
  const userId = request.user!.id;

  const { data, error } = await supabaseAdmin
    .from("user_analyses")
    .select("*")
    .eq("user_id", userId)
    .order("created_at", { ascending: false });

  if (error) return reply.code(500).send({ error: error.message });
  return { data };
});

app.post("/v1/analyses", { preHandler: requireUser }, async (request: AuthedRequest, reply: FastifyReply) => {
  const schema = z.object({
    marketplace: z.string().min(1),
    file_name: z.string().min(1),
    analysis_data: z.any().optional(),
    summary: z.any().optional(),
  });

  const parsed = schema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({ error: "Invalid body", details: parsed.error.flatten() });
  }

  const userId = request.user!.id;
  const body = parsed.data;

  const analysisJson = JSON.stringify(body.analysis_data ?? {});
  const { data, error } = await supabaseAdmin
    .from("user_analyses")
    .insert({
      user_id: userId,
      marketplace: body.marketplace,
      file_name: body.file_name,
      analysis_data: body.analysis_data ?? null,
      summary: body.summary ?? null,
      data_size_bytes: analysisJson.length,
    })
    .select("*")
    .single();

  if (error) return reply.code(500).send({ error: error.message });
  return { data };
});

// ===== Boot =====
async function main() {
  await app.register(cors, {
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);

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