/**
 * Fastify API Server — Entry Point
 *
 * Starts a Fastify server with CORS, rate limiting, and transaction routes.
 * Also exports a Vercel serverless handler for deployment.
 */
import "dotenv/config";
import Fastify from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import { txRoutes } from "./routes/tx.js";

// ----- Create Fastify instance -----
const app = Fastify({
  logger: true,
});

// Enable CORS for the frontend
await app.register(cors, {
  origin: true, // Allow all origins in dev; configure for production
  methods: ["GET", "POST"],
});

// Register rate limiting plugin (applied per-route via route config)
await app.register(rateLimit, {
  global: false, // Don't apply globally — only to routes that opt-in
});

// Register transaction routes
await app.register(txRoutes);

// Health check endpoint
app.get("/health", async () => ({ status: "ok" }));

// ----- Local development server -----

const PORT = Number(process.env.PORT) || 3001;

// Only start server in local development (not in Vercel serverless)
if (!process.env.VERCEL) {
  try {
    await app.listen({ port: PORT, host: "0.0.0.0" });
    console.log(`🚀 API server running at http://localhost:${PORT}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

// ----- Vercel serverless handler export -----

export default async function handler(req, res) {
  await app.ready();
  
  // Use Fastify's inject method for serverless compatibility
  const response = await app.inject({
    method: req.method,
    url: req.url,
    headers: req.headers,
    payload: req.body,
  });

  res.statusCode = response.statusCode;
  Object.keys(response.headers).forEach((key) => {
    res.setHeader(key, response.headers[key]);
  });
  res.end(response.body);
}
