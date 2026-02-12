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
app.get("/", async () => ({ ok: true, service: "profit-clarity-api" }));
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

// ✅ CADASTRO (signup)
app.post("/v1/auth/signup", async (request: FastifyRequest, reply: FastifyReply) => {
  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
    // Metadata flexível - aceita qualquer campo extra do formulário
    name: z.string().optional(),
    full_name: z.string().optional(),
    phone: z.string().optional(),
    phone_e164: z.string().optional(),
    city: z.string().optional(),
    uf: z.string().optional(),
    cep: z.string().optional(),
    address_street: z.string().optional(),
    address_number: z.string().optional(),
    address_complement: z.string().nullable().optional(),
    address_neighborhood: z.string().nullable().optional(),
    address_city: z.string().optional(),
    address_state: z.string().optional(),
  });

  const parsed = schema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({ error: "Invalid body", details: parsed.error.flatten() });
  }

  const { email, password, ...rest } = parsed.data;

  const { data: created, error: createErr } = await supabaseAdmin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: rest,
  });

  if (createErr) {
    return reply.code(400).send({ error: createErr.message });
  }

  const { data: sessionData, error: loginErr } = await supabaseAdmin.auth.signInWithPassword({
    email,
    password,
  });

  if (loginErr || !sessionData.session) {
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

// ✅ ALIAS /register
app.post("/v1/auth/register", async (request: FastifyRequest, reply: FastifyReply) => {
  const res = await app.inject({
    method: "POST",
    url: "/v1/auth/signup",
    payload: request.body as any,
    headers: request.headers as any,
  });

  reply.code(res.statusCode).headers(res.headers).send(res.json());
});

// ✅ Busca custos de produtos por SKU (usa service role, ignora RLS)
app.post("/v1/products/costs", { preHandler: requireUser }, async (request: AuthedRequest, reply: FastifyReply) => {
  const schema = z.object({
    skus: z.array(z.string()).min(1).max(5000),
  });

  const parsed = schema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({ error: "Invalid body", details: parsed.error.flatten() });
  }

  const { skus } = parsed.data;

  // Supabase tem limite de ~1000 items no .in(), então dividimos em chunks
  const CHUNK_SIZE = 500;
  let allProducts: any[] = [];

  for (let i = 0; i < skus.length; i += CHUNK_SIZE) {
    const chunk = skus.slice(i, i + CHUNK_SIZE);

    const { data, error } = await supabaseAdmin
      .from("wedrop_products2")
      .select("SKU, Produto, preco_custo_num, preco_custo_impostos_num, preco_venda_num, Multiplicador_flex")
      .in("SKU", chunk);

    if (error) {
      // Se der erro na coluna Multiplicador_flex, tenta sem ela
      if (error.message?.includes("Multiplicador_flex")) {
        const fallback = await supabaseAdmin
          .from("wedrop_products2")
          .select("SKU, Produto, preco_custo_num, preco_custo_impostos_num, preco_venda_num")
          .in("SKU", chunk);

        if (fallback.error) {
          return reply.code(500).send({ error: fallback.error.message });
        }
        allProducts = allProducts.concat(fallback.data || []);
        continue;
      }
      return reply.code(500).send({ error: error.message });
    }

    allProducts = allProducts.concat(data || []);
  }

  return { data: allProducts };
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

// ✅ Busca uma análise por ID (com analysis_data completo)
app.get("/v1/analyses/:id", { preHandler: requireUser }, async (request: AuthedRequest, reply: FastifyReply) => {
  const { id } = request.params as { id: string };
  const userId = request.user!.id;

  const { data, error } = await supabaseAdmin
    .from("user_analyses")
    .select("*")
    .eq("id", id)
    .eq("user_id", userId)
    .single();

  if (error) {
    if (error.code === "PGRST116") {
      return reply.code(404).send({ error: "Análise não encontrada" });
    }
    return reply.code(500).send({ error: error.message });
  }

  return { data };
});

// ✅ Deleta uma análise por ID
app.delete("/v1/analyses/:id", { preHandler: requireUser }, async (request: AuthedRequest, reply: FastifyReply) => {
  const { id } = request.params as { id: string };
  const userId = request.user!.id;

  const { error } = await supabaseAdmin
    .from("user_analyses")
    .delete()
    .eq("id", id)
    .eq("user_id", userId);

  if (error) {
    return reply.code(500).send({ error: error.message });
  }

  return reply.code(204).send();
});

// ===== Boot =====
async function main() {
  await app.register(cors, {
    origin: (origin, cb) => {
      // chamadas server-to-server / curl / postman não mandam origin
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
    // deixa completo pra não te ferrar depois (browser pode pedir outros)
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  });

  // ❌ REMOVIDO: app.options("*"...)
  // O @fastify/cors já cria o preflight. Esse era o motivo do erro.

  await app.listen({ port: PORT, host: "0.0.0.0" });
  app.log.info(`🚀 API local rodando em http://localhost:${PORT}`);
}

main().catch((err) => {
  app.log.error(err);
  process.exit(1);
});