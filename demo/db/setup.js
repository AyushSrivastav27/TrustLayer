import Database from 'better-sqlite3';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DB_PATH = path.join(__dirname, 'quickshop.db');

export const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');

/**
 * Initializes database tables and seed data for the QuickShop demo application.
 */
export function initDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      category TEXT,
      stock INTEGER DEFAULT 100,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      quantity INTEGER DEFAULT 1,
      amount REAL NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (product_id) REFERENCES products(id)
    );
  `);

  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;

  if (userCount === 0) {
    const insertUser = db.prepare(`
      INSERT INTO users (name, email, password, role)
      VALUES (@name, @email, @password, @role)
    `);

    const hashPassword = (pwd) => crypto.createHash('sha256').update(pwd).digest('hex');

    insertUser.run({
      name: 'System Administrator',
      email: 'admin@quickshop.com',
      password: hashPassword('admin123'),
      role: 'admin'
    });

    insertUser.run({
      name: 'Alice Johnson',
      email: 'alice@example.com',
      password: hashPassword('password123'),
      role: 'user'
    });

    insertUser.run({
      name: 'Bob Smith',
      email: 'bob@example.com',
      password: hashPassword('bob123'),
      role: 'user'
    });
  }

  const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get().count;

  if (productCount === 0) {
    const insertProduct = db.prepare(`
      INSERT INTO products (name, description, price, category, stock)
      VALUES (@name, @description, @price, @category, @stock)
    `);

    insertProduct.run({
      name: 'Mechanical Keyboard Pro',
      description: 'Tactile mechanical switches with RGB backlighting',
      price: 129.99,
      category: 'Peripherals',
      stock: 50
    });

    insertProduct.run({
      name: 'Wireless Ergonomic Mouse',
      description: 'Precision optical sensor with multi-device pairing',
      price: 59.99,
      category: 'Peripherals',
      stock: 80
    });

    insertProduct.run({
      name: 'Ultra-Wide 34-inch Curved Monitor',
      description: '144Hz refresh rate, HDR 400 gaming monitor',
      price: 499.99,
      category: 'Displays',
      stock: 20
    });

    insertProduct.run({
      name: 'USB-C 7-in-1 Hub Adapter',
      description: 'HDMI 4K, 100W Power Delivery, SD Card Reader',
      price: 39.99,
      category: 'Accessories',
      stock: 120
    });

    insertProduct.run({
      name: 'Noise-Cancelling Over-Ear Headphones',
      description: 'Active noise cancellation with 30-hour battery life',
      price: 199.99,
      category: 'Audio',
      stock: 45
    });
  }

  const orderCount = db.prepare('SELECT COUNT(*) as count FROM orders').get().count;

  if (orderCount === 0) {
    const insertOrder = db.prepare(`
      INSERT INTO orders (user_id, product_id, quantity, amount, status)
      VALUES (@user_id, @product_id, @quantity, @amount, @status)
    `);

    insertOrder.run({
      user_id: 2,
      product_id: 1,
      quantity: 1,
      amount: 129.99,
      status: 'completed'
    });

    insertOrder.run({
      user_id: 3,
      product_id: 3,
      quantity: 1,
      amount: 499.99,
      status: 'pending'
    });
  }

  return db;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  initDatabase();
  console.log('Database initialized successfully at:', DB_PATH);
}

export default db;
