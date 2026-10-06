import express from 'express';
import cors from 'cors';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { initDatabase, db } from './db/setup.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

initDatabase();

const ROUTE_DEFINITIONS = [
  { prefix: '/api/auth', file: 'routes/auth.js' },
  { prefix: '/api/products', file: 'routes/products.js' },
  { prefix: '/api/orders', file: 'routes/orders.js' },
  { prefix: '/api/checkout', file: 'routes/checkout.js' },
  { prefix: '/api/webhook', file: 'routes/webhook.js' }
];

export async function mountRoutes(expressApp) {
  for (const { prefix, file } of ROUTE_DEFINITIONS) {
    const fullPath = path.join(__dirname, file);

    if (fs.existsSync(fullPath)) {
      try {
        const routeModule = await import(pathToFileURL(fullPath).href);
        const router = routeModule.default || routeModule.router;

        if (router) {
          expressApp.use(prefix, router);
          console.log(`[QuickShop] Mounted: ${prefix} -> ${file}`);
        }
      } catch (err) {
        console.warn(`[QuickShop] Failed to load route ${file}:`, err.message);
      }
    } else {
      // Graceful fallback for uncompleted routes
      expressApp.use(prefix, (req, res) => {
        res.status(501).json({
          error: 'Not Implemented',
          message: `The ${prefix} route is under construction.`
        });
      });
    }
  }
}

app.get('/', (req, res) => {
  res.json({
    app: 'QuickShop E-Commerce API',
    version: '1.0.0',
    description: 'Reference application for TrustLayer security demonstration',
    status: 'running',
    endpoints: {
      health: '/health',
      auth: '/api/auth',
      products: '/api/products',
      orders: '/api/orders',
      checkout: '/api/checkout',
      webhook: '/api/webhook'
    }
  });
});

app.get('/health', (req, res) => {
  try {
    const check = db.prepare('SELECT 1 as alive').get();
    res.json({
      status: 'ok',
      service: 'QuickShop API',
      database: check.alive === 1 ? 'connected' : 'disconnected',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ status: 'error', database: err.message });
  }
});

app.use((err, req, res, next) => {
  console.error('[QuickShop Error]', err.stack || err.message);
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message
  });
});

export async function startServer() {
  await mountRoutes(app);

  return new Promise((resolve) => {
    const server = app.listen(PORT, () => {
      console.log(`\n🛍️  QuickShop Demo API running at http://localhost:${PORT}`);
      console.log(`   Healthcheck: http://localhost:${PORT}/health\n`);
      resolve(server);
    });
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  startServer();
}

export default app;
