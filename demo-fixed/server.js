import express from 'express';
import cors from 'cors';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { db } from '../demo/db/setup.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
          console.log(`[QuickShop-Fixed] Mounted: ${prefix} -> ${file}`);
        }
      } catch (err) {
        console.warn(`[QuickShop-Fixed] Failed to load route ${file}:`, err.message);
      }
    }
  }
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'QuickShop Fixed Reference API' });
});

export default app;
