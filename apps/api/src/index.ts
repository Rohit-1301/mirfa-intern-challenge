/**
 * Fastify API Server — Entry Point
 *
 * Starts a Fastify server with CORS enabled and transaction routes registered.
 * Also exports a Vercel serverless handler for deployment.
 */

import "dotenv/config";
import Fastify from "fastify";
import cors from "@fastify/cors";
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

// Register transaction routes
await app.register(txRoutes);

// Health check endpoint
app.get("/health", async () => ({ status: "ok" }));

// ----- Local development server -----

const PORT = Number(process.env.PORT) || 3001;

try {
  await app.listen({ port: PORT, host: "0.0.0.0" });
  console.log(`🚀 API server running at http://localhost:${PORT}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}

// ----- Vercel serverless handler export -----

export default async function handler(req: any, res: any) {
  await app.ready();
  app.server.emit("request", req, res);
}
