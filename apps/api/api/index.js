// Vercel serverless function wrapper
// This imports the Fastify handler from the compiled dist folder

export default async function handler(req, res) {
  // Dynamically import the ES module handler
  const { default: fastifyHandler } = await import('../dist/index.js');
  return fastifyHandler(req, res);
}
