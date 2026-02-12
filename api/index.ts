import "dotenv/config";
import Fastify from "fastify";
import cors from "@fastify/cors";
import { createClient } from "@supabase/supabase-js";
import { z } from "zod";

// cache pra não recriar app a cada request (melhora performance na Vercel)
let cachedApp: any = null;

async function buildApp() {
  const app = Fastify({ logger: true });

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("Missing env: SUPABASE_URL and/or SUPABASE_SERVICE_ROLE_KEY");
  }

  const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

  // ===== Helpers =====
  type AuthedRequest = any & { user?: { id: string; email?: string } };

  async function requireUser(request: AuthedRequest, reply: any) {
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

  // ===== CORS =====
  await app.register(cors, {
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);

      const allowed = [
        /^http:\/\/localhost:\d+$/,
        /^https:\/\/.*\.vercel\.app$/,
        /^https:\/\/(.*\.)?wcontrol\.app\.br$/,
      ];

      cb(null, allowed.some((re) => re.test(origin)));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  });

  // ===== Routes =====
  app.get("/", async () => ({ ok: true, service: "profit-clarity-api" }));
  app.get("/v1/health", async () => ({ ok: true }));

  app.get("/v1/auth/me", { preHandler: requireUser }, async (request: AuthedRequest) => {
    return { user: request.user };
  });

  // ===== Login =====
  app.post("/v1/auth/login", async (request: any, reply: any) => {
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

  // ===== Signup =====
  app.post("/v1/auth/signup", async (request: any, reply: any) => {
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

  // ===== Register alias =====
  app.post("/v1/auth/register", async (request: any, reply: any) => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/signup",
      payload: request.body,
      headers: request.headers,
    });

    reply.code(res.statusCode).headers(res.headers).send(res.json());
  });

  // ===== Busca custos de produtos por SKU (usa service role, ignora RLS) =====
  app.post("/v1/products/costs", { preHandler: requireUser }, async (request: AuthedRequest, reply: any) => {
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

  // ===== Listar análises =====
  app.get("/v1/analyses", { preHandler: requireUser }, async (request: AuthedRequest, reply: any) => {
    const userId = request.user!.id;

    const { data, error } = await supabaseAdmin
      .from("user_analyses")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false });

    if (error) return reply.code(500).send({ error: error.message });
    return { data };
  });

  // ===== Criar análise =====
  app.post("/v1/analyses", { preHandler: requireUser }, async (request: AuthedRequest, reply: any) => {
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

  // ===== Buscar análise por ID =====
  app.get("/v1/analyses/:id", { preHandler: requireUser }, async (request: AuthedRequest, reply: any) => {
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

  // ===== Deletar análise por ID =====
  app.delete("/v1/analyses/:id", { preHandler: requireUser }, async (request: AuthedRequest, reply: any) => {
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

  await app.ready();
  return app;
}

export default async function handler(req: any, res: any) {
  if (!cachedApp) cachedApp = await buildApp();

  // Vercel manda req.url com "/api/..." — precisamos cortar o "/api"
  const rawUrl = req.url || "/";
  const url = rawUrl.startsWith("/api") ? rawUrl.slice(4) || "/" : rawUrl;

  const result = await cachedApp.inject({
    method: req.method,
    url,
    headers: req.headers,
    payload: req.body,
  });

  res.statusCode = result.statusCode;

  for (const [key, value] of Object.entries(result.headers || {})) {
    if (value !== undefined) res.setHeader(key, String(value));
  }

  res.end(result.payload);
}
