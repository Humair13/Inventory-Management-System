
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const session = require('express-session');
const path = require('path');

const app = express();

app.use(express.json());
app.use(cors({
  origin: ['http://localhost:5000', 'http://127.0.0.1:5000'],
  credentials: true
}));
app.use(session({
  secret: 'inventory-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// Serve inventory.html at http://localhost:5000
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'inventory.html'));
});

// Connect to database
const db = new sqlite3.Database('./Login_System.db', (err) => {
  if (err) console.error('DB connection error:', err.message);
  else console.log('✅ Connected to Login_System.db');
});
db.serialize(() => {
  // USERS
  db.run(`
    CREATE TABLE IF NOT EXISTS Users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      first_name TEXT,
      last_name TEXT,
      business_name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      gst_number TEXT,
      city TEXT,
      low_stock_threshold INTEGER DEFAULT 10,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // PRODUCTS
  db.run(`
    CREATE TABLE IF NOT EXISTS Products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      sku TEXT,
      category_id INTEGER,
      supplier_id INTEGER,
      unit TEXT,
      buy_price REAL,
      sell_price REAL,
      stock INTEGER,
      min_stock INTEGER,
      description TEXT
    )
  `);

  // CATEGORIES
  db.run(`
  CREATE TABLE IF NOT EXISTS Categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    icon TEXT DEFAULT '📦'
    )
  `);

  // SUPPLIERS
  db.run(`
    CREATE TABLE IF NOT EXISTS Suppliers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      contact TEXT,
      email TEXT,
      city TEXT,
      gst TEXT
    )
  `);

  // ORDERS
  db.run(`
    CREATE TABLE IF NOT EXISTS Orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER,
      type TEXT,
      quantity INTEGER,
      price REAL,
      total REAL,
      notes TEXT,
      status TEXT DEFAULT 'completed',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // TRANSACTIONS
  db.run(`
    CREATE TABLE IF NOT EXISTS Transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      description TEXT,
      type TEXT,
      amount REAL,
      balance REAL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  console.log("✅ All tables ready");
});
// ─── AUTH GUARD ───────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────

// REGISTER
// Users table: id, first_name(NN), last_name(NN), business_name(NN), email(NN,UNIQUE), password(NN), gst_number, city, low_stock_threshold, created_at
app.post('/api/register', async (req, res) => {
  const { firstName, lastName, businessName, email, password } = req.body;
  if (!firstName || !email || !password)
    return res.status(400).json({ error: 'First name, email and password are required' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    db.run(
      `INSERT INTO Users (first_name, last_name, business_name, email, password)
       VALUES (?, ?, ?, ?, ?)`,
      [
        firstName.trim(),
        (lastName || '').trim(),
        (businessName || '').trim(),
        email.trim().toLowerCase(),
        hashed
      ],
      function (err) {
        if (err) {
          console.error('Register error:', err.message);
          if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Email already registered' });
          return res.status(500).json({ error: err.message });
        }
        req.session.userId = this.lastID;
        console.log('✅ New user registered, id:', this.lastID);
        res.json({ success: true });
      }
    );
  } catch (e) {
    console.error('Register exception:', e.message);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// LOGIN
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  db.get(`SELECT * FROM Users WHERE email = ?`, [email.trim().toLowerCase()], async (err, user) => {
    if (err) { console.error('Login error:', err.message); return res.status(500).json({ error: 'Server error' }); }
    if (!user) return res.status(400).json({ error: 'User not found' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid password' });
    req.session.userId = user.id;
    console.log('✅ User logged in, id:', user.id);
    res.json({ success: true });
  });
});

// LOGOUT
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// GET current user
app.get('/api/me', requireAuth, (req, res) => {
  db.get(`SELECT * FROM Users WHERE id = ?`, [req.session.userId], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Not authenticated' });
    delete user.password;
    res.json(user);
  });
});

// UPDATE profile/settings
app.put('/api/me', requireAuth, (req, res) => {
  const { firstName, lastName, businessName, gstNumber, city, lowStockThreshold } = req.body;
  db.run(
    `UPDATE Users SET first_name=?, last_name=?, business_name=?, gst_number=?, city=?, low_stock_threshold=? WHERE id=?`,
    [
      firstName || '',
      lastName || '',
      businessName || '',
      gstNumber || '',
      city || '',
      lowStockThreshold || 10,
      req.session.userId
    ],
    (err) => {
      if (err) { console.error('Update user error:', err.message); return res.status(500).json({ error: err.message }); }
      res.json({ success: true });
    }
  );
});

// ─── PRODUCTS ─────────────────────────────────────────────────────────────────
// Table cols: id, name(NN), sku, category_id, supplier_id, unit, buy_price(NN), sell_price(NN), stock(NN), min_stock, description

app.get('/api/products', requireAuth, (req, res) => {
  db.all(`SELECT * FROM Products ORDER BY id DESC`, [], (err, rows) => {
    if (err) console.error('Get products error:', err.message);
    res.json(rows || []);
  });
});

app.post('/api/products', requireAuth, (req, res) => {
  const { name, sku, categoryId, supplierId, unit, buyPrice, sellPrice, stock, minStock, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Product name is required' });
  db.run(
    `INSERT INTO Products (name, sku, category_id, supplier_id, unit, buy_price, sell_price, stock, min_stock, description)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [name, sku || '', categoryId || null, supplierId || null, unit || 'Pieces', buyPrice || 0, sellPrice || 0, stock || 0, minStock || 10, description || ''],
    function (err) {
      if (err) { console.error('Add product error:', err.message); return res.status(500).json({ error: err.message }); }
      console.log('✅ Product added, id:', this.lastID);
      res.json({ id: this.lastID });
    }
  );
});

app.put('/api/products/:id', requireAuth, (req, res) => {
  const { name, sku, categoryId, supplierId, unit, buyPrice, sellPrice, stock, minStock, description } = req.body;
  db.run(
    `UPDATE Products SET name=?, sku=?, category_id=?, supplier_id=?, unit=?, buy_price=?, sell_price=?, stock=?, min_stock=?, description=? WHERE id=?`,
    [name, sku || '', categoryId || null, supplierId || null, unit || 'Pieces', buyPrice || 0, sellPrice || 0, stock || 0, minStock || 10, description || '', req.params.id],
    (err) => {
      if (err) { console.error('Update product error:', err.message); return res.status(500).json({ error: err.message }); }
      res.json({ success: true });
    }
  );
});

app.delete('/api/products/:id', requireAuth, (req, res) => {
  db.run(`DELETE FROM Products WHERE id=?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ─── CATEGORIES ───────────────────────────────────────────────────────────────
// Table cols: id, name, icon

app.get('/api/categories', requireAuth, (req, res) => {
  db.all(`SELECT * FROM Categories ORDER BY name`, [], (err, rows) => {
    res.json(rows || []);
  });
});

app.post('/api/categories', requireAuth, (req, res) => {
  const { name, icon } = req.body;
  if (!name) return res.status(400).json({ error: 'Category name required' });
  db.run(`INSERT INTO Categories (name, icon) VALUES (?, ?)`, [name, icon || '📦'], function (err) {
    if (err) { console.error('Add category error:', err.message); return res.status(500).json({ error: err.message }); }
    console.log('✅ Category added, id:', this.lastID);
    res.json({ id: this.lastID });
  });
});

app.delete('/api/categories/:id', requireAuth, (req, res) => {
  db.run(`DELETE FROM Categories WHERE id=?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ─── SUPPLIERS ────────────────────────────────────────────────────────────────
// Table cols: id, name, contact, email, city, gst
// Frontend expects: contact_person, gst_number, phone → aliased in SELECT

app.get('/api/suppliers', requireAuth, (req, res) => {
  db.all(
    `SELECT id, name, contact AS contact_person, email, city, gst AS gst_number, '' AS phone FROM Suppliers ORDER BY name`,
    [],
    (err, rows) => {
      if (err) console.error('Get suppliers error:', err.message);
      res.json(rows || []);
    }
  );
});

app.post('/api/suppliers', requireAuth, (req, res) => {
  const { name, contactPerson, email, phone, city, gstNumber } = req.body;
  if (!name) return res.status(400).json({ error: 'Supplier name required' });
  // phone column may not exist yet — store in contact field if needed
  db.run(
    `INSERT INTO Suppliers (name, contact, email, city, gst) VALUES (?, ?, ?, ?, ?)`,
    [name, contactPerson || '', email || '', city || '', gstNumber || ''],
    function (err) {
      if (err) { console.error('Add supplier error:', err.message); return res.status(500).json({ error: err.message }); }
      console.log('✅ Supplier added, id:', this.lastID);
      res.json({ id: this.lastID });
    }
  );
});

app.delete('/api/suppliers/:id', requireAuth, (req, res) => {
  db.run(`DELETE FROM Suppliers WHERE id=?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ─── ORDERS ───────────────────────────────────────────────────────────────────
// Table cols: id, product_id, type, quantity, price, total, notes, status, created_at

app.get('/api/orders', requireAuth, (req, res) => {
  db.all(
    `SELECT o.*, p.name AS product_name
     FROM Orders o
     LEFT JOIN Products p ON o.product_id = p.id
     ORDER BY o.id DESC`,
    [],
    (err, rows) => {
      if (err) console.error('Get orders error:', err.message);
      res.json(rows || []);
    }
  );
});

app.post('/api/orders', requireAuth, (req, res) => {
  const { productId, type, quantity, unitPrice, notes } = req.body;
  if (!productId || !quantity || !unitPrice) return res.status(400).json({ error: 'Product, quantity and price are required' });
  const total = quantity * unitPrice;

  db.get(`SELECT name FROM Products WHERE id=?`, [productId], (err, product) => {
    if (!product) return res.status(400).json({ error: 'Product not found' });

    db.run(
      `INSERT INTO Orders (product_id, type, quantity, price, total, notes) VALUES (?, ?, ?, ?, ?, ?)`,
      [productId, type, quantity, unitPrice, total, notes || ''],
      function (orderErr) {
        if (orderErr) { console.error('Add order error:', orderErr.message); return res.status(500).json({ error: orderErr.message }); }

        // Update stock level
        const stockChange = type === 'sale' ? -quantity : quantity;
        db.run(`UPDATE Products SET stock = stock + ? WHERE id=?`, [stockChange, productId]);

        // Record in Transactions — only use columns that exist: id, description, type, amount, balance, created_at
        const txType = type === 'sale' ? 'credit' : 'debit';
        const desc = type === 'sale'
          ? `Sale: ${product.name} x${quantity}`
          : `Purchase: ${product.name} x${quantity}`;
        db.run(
          `INSERT INTO Transactions (description, type, amount, balance) VALUES (?, ?, ?, 0)`,
          [desc, txType, total]
        );

        console.log('✅ Order added, id:', this.lastID, '| Total:', total);
        res.json({ id: this.lastID, total });
      }
    );
  });
});

// ─── TRANSACTIONS ─────────────────────────────────────────────────────────────
// Table cols: id, description, type, amount, balance, created_at

app.get('/api/transactions', requireAuth, (req, res) => {
  db.all(`SELECT * FROM Transactions ORDER BY id DESC LIMIT 100`, [], (err, rows) => {
    if (err) console.error('Get transactions error:', err.message);
    res.json(rows || []);
  });
});

// ─── STATS ────────────────────────────────────────────────────────────────────

app.get('/api/stats', requireAuth, (req, res) => {
  db.get(`SELECT COUNT(*) AS total, COALESCE(SUM(sell_price * stock), 0) AS value FROM Products`, [], (err, row1) => {
    db.get(`SELECT COUNT(*) AS low FROM Products WHERE stock <= COALESCE(min_stock, 10)`, [], (err2, row2) => {
      db.get(`SELECT COUNT(*) AS cats FROM Categories`, [], (err3, row3) => {
        res.json({
          total: (row1 && row1.total) || 0,
          value: (row1 && row1.value) || 0,
          low:   (row2 && row2.low)   || 0,
          cats:  (row3 && row3.cats)  || 0
        });
      });
    });
  });
});

// ─── START ────────────────────────────────────────────────────────────────────

app.listen(5000, () => {
  console.log('✅ Server running → http://localhost:5000');

});