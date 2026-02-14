/**
 * Vercel Serverless Function for Fastify API
 * Uses lazy initialization to avoid top-level await issues
 */
import "dotenv/config";
import Fastify from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import { txRoutes } from "./routes/tx.js";

let app;

async function buildApp() {
  if (app) return app;

  app = Fastify({
    logger: true,
  });

  // Enable CORS
  await app.register(cors, {
    origin: true,
    methods: ["GET", "POST"],
  });

  // Register rate limiting
  await app.register(rateLimit, {
    global: false,
  });

  // Register transaction routes
  await app.register(txRoutes);

  // Health check endpoint
  app.get("/health", async () => ({ status: "ok" }));

  await app.ready();
  return app;
}

// Vercel serverless handler
export default async function handler(req, res) {
  const fastify = await buildApp();
  
  const response = await fastify.inject({
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
