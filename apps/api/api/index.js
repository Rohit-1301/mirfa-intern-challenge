/**
 * Vercel Serverless Function - API Handler
 * Standalone version that doesn't rely on complex imports
 */

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // Health check
  if (req.url === '/health') {
    res.status(200).json({ status: 'ok' });
    return;
  }

  // Import and use the actual Fastify app
  try {
    const { default: fastifyHandler } = await import('./dist/index.js');
    return fastifyHandler(req, res);
  } catch (error) {
    console.error('Error loading Fastify app:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
}
