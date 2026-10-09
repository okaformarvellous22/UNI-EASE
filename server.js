
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'campus-assist.sqlite');
const db = new DatabaseSync(DB_PATH);

db.exec(`
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('customer','worker','admin')),
  phone TEXT DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  worker_id INTEGER,
  service TEXT NOT NULL,
  description TEXT NOT NULL,
  pickup TEXT DEFAULT '',
  delivery TEXT NOT NULL,
  price INTEGER NOT NULL DEFAULT 1500,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','assigned','accepted','in_progress','completed','cancelled','problem')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(customer_id) REFERENCES users(id),
  FOREIGN KEY(worker_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS order_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  actor_id INTEGER,
  status TEXT NOT NULL,
  note TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY(actor_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS complaints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  customer_id INTEGER NOT NULL,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','investigating','resolved')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY(customer_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS ratings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL UNIQUE,
  customer_id INTEGER NOT NULL,
  worker_id INTEGER,
  rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
  comment TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
);
`);

const seed = db.prepare('SELECT COUNT(*) AS n FROM users').get();
if (seed.n === 0) {
  const hash = (p) => crypto.createHash('sha256').update(p).digest('hex');
  const ins = db.prepare('INSERT INTO users(name,email,password_hash,role,phone) VALUES(?,?,?,?,?)');
  ins.run('Campus Assist Admin','admin@campusassist.local',hash('admin123'),'admin','');
  ins.run('Demo Worker','worker@campusassist.local',hash('worker123'),'worker','08000000000');
  ins.run('Demo Customer','customer@campusassist.local',hash('customer123'),'customer','08168125418');
}

const sessions = new Map();

function send(res, status, data, type='application/json') {
  res.writeHead(status, {'Content-Type': type, 'Cache-Control':'no-store'});
  res.end(type === 'application/json' ? JSON.stringify(data) : data);
}
function hashPassword(p) { return crypto.createHash('sha256').update(p).digest('hex'); }
function token() { return crypto.randomBytes(32).toString('hex'); }
function body(req) {
  return new Promise((resolve,reject)=>{
    let s='';
    req.on('data',c=>{s+=c});
    req.on('end',()=>{try{resolve(s?JSON.parse(s):{})}catch(e){reject(e)}});
  });
}
function auth(req) {
  const t = req.headers.authorization?.replace(/^Bearer\s+/,'');
  const uid = sessions.get(t);
  if (!uid) return null;
  return db.prepare('SELECT id,name,email,role,phone,active FROM users WHERE id=?').get(uid);
}
function requireRole(user, roles) { return user && roles.includes(user.role); }
function safeUser(u){ return {id:u.id,name:u.name,email:u.email,role:u.role,phone:u.phone||''}; }

function createEvent(orderId, actorId, status, note='') {
  db.prepare('INSERT INTO order_events(order_id,actor_id,status,note) VALUES(?,?,?,?)')
    .run(orderId, actorId || null, status, note);
  db.prepare('UPDATE orders SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status, orderId);
}

async function api(req,res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;
  try {
    if (req.method === 'POST' && p === '/api/signup') {
      const b = await body(req);
      if (!b.name || !b.email || !b.password) return send(res,400,{error:'Name, email and password are required.'});
      if (b.password.length < 6) return send(res,400,{error:'Password must be at least 6 characters.'});
      const email=b.email.trim().toLowerCase();
      try {
        const r=db.prepare('INSERT INTO users(name,email,password_hash,role,phone) VALUES(?,?,?,?,?)')
          .run(b.name.trim(),email,hashPassword(b.password),'customer',b.phone||'');
        const u=db.prepare('SELECT id,name,email,role,phone FROM users WHERE id=?').get(r.lastInsertRowid);
        const t=token(); sessions.set(t,u.id);
        return send(res,201,{token:t,user:safeUser(u)});
      } catch(e) { return send(res,409,{error:'That email is already registered.'}); }
    }
    if (req.method === 'POST' && p === '/api/login') {
      const b=await body(req);
      const u=db.prepare('SELECT * FROM users WHERE email=? AND password_hash=?')
        .get((b.email||'').trim().toLowerCase(),hashPassword(b.password||''));
      if (!u || !u.active) return send(res,401,{error:'Invalid login details.'});
      const t=token(); sessions.set(t,u.id);
      return send(res,200,{token:t,user:safeUser(u)});
    }
    if (req.method === 'POST' && p === '/api/logout') {
      const t=req.headers.authorization?.replace(/^Bearer\s+/,''); sessions.delete(t); return send(res,200,{ok:true});
    }

    const user=auth(req);
    if (!user) return send(res,401,{error:'Please log in.'});

    if (req.method === 'GET' && p === '/api/me') return send(res,200,{user:safeUser(user)});

    if (req.method === 'GET' && p === '/api/services') {
      return send(res,200,{services:[
        {name:'Parcel Pickup',base:1500},
        {name:'Printing / Photocopy',base:1500},
        {name:'Assignment / Document Drop-off',base:1500},
        {name:'Queue as a Service',base:3999},
        {name:'Food / Grocery Run',base:1500},
        {name:'General Campus Errand',base:1500}
      ]});
    }

    if (req.method === 'POST' && p === '/api/orders') {
      if (!requireRole(user,['customer'])) return send(res,403,{error:'Only customers can create orders.'});
      const b=await body(req);
      if (!b.service || !b.description || !b.delivery) return send(res,400,{error:'Service, description and delivery location are required.'});
      const price=Math.max(0,Number(b.price)||1500);
      const r=db.prepare(`INSERT INTO orders(customer_id,service,description,pickup,delivery,price,status)
        VALUES(?,?,?,?,?,?,?)`).run(user.id,b.service,b.description,b.pickup||'',b.delivery,price,'pending');
      createEvent(r.lastInsertRowid,user.id,'pending','Order created');
      return send(res,201,{orderId:Number(r.lastInsertRowid)});
    }

    if (req.method === 'GET' && p === '/api/orders') {
      let rows;
      if (user.role==='customer') {
        rows=db.prepare(`SELECT o.*, w.name worker_name FROM orders o LEFT JOIN users w ON w.id=o.worker_id
          WHERE o.customer_id=? ORDER BY o.id DESC`).all(user.id);
      } else if (user.role==='worker') {
        rows=db.prepare(`SELECT o.*, c.name customer_name, c.phone customer_phone FROM orders o
          JOIN users c ON c.id=o.customer_id WHERE o.worker_id=? OR (o.worker_id IS NULL AND o.status='pending')
          ORDER BY o.id DESC`).all(user.id);
      } else {
        rows=db.prepare(`SELECT o.*, c.name customer_name, c.phone customer_phone, w.name worker_name
          FROM orders o JOIN users c ON c.id=o.customer_id LEFT JOIN users w ON w.id=o.worker_id
          ORDER BY o.id DESC`).all();
      }
      return send(res,200,{orders:rows});
    }

    const orderMatch=p.match(/^\/api\/orders\/(\d+)(?:\/(accept|status))?$/);
    if (orderMatch && req.method === 'GET') {
      const id=Number(orderMatch[1]);
      const o=db.prepare(`SELECT o.*, c.name customer_name,c.phone customer_phone,w.name worker_name
        FROM orders o JOIN users c ON c.id=o.customer_id LEFT JOIN users w ON w.id=o.worker_id WHERE o.id=?`).get(id);
      if (!o) return send(res,404,{error:'Order not found.'});
      if (user.role==='customer' && o.customer_id!==user.id) return send(res,403,{error:'Not allowed.'});
      if (user.role==='worker' && o.worker_id!==user.id && o.status!=='pending') return send(res,403,{error:'Not allowed.'});
      const events=db.prepare(`SELECT e.*,u.name actor_name FROM order_events e LEFT JOIN users u ON u.id=e.actor_id
        WHERE e.order_id=? ORDER BY e.id ASC`).all(id);
      return send(res,200,{order:o,events});
    }

    if (orderMatch && req.method === 'POST' && p.endsWith('/accept')) {
      if (user.role!=='worker') return send(res,403,{error:'Workers only.'});
      const id=Number(orderMatch[1]);
      const o=db.prepare('SELECT * FROM orders WHERE id=?').get(id);
      if (!o || (o.worker_id && o.worker_id!==user.id)) return send(res,404,{error:'Order unavailable.'});
      db.prepare('UPDATE orders SET worker_id=? WHERE id=?').run(user.id,id);
      createEvent(id,user.id,'accepted','Worker accepted the order');
      return send(res,200,{ok:true});
    }

    if (orderMatch && req.method === 'POST' && p.endsWith('/status')) {
      if (!requireRole(user,['worker','admin'])) return send(res,403,{error:'Not allowed.'});
      const id=Number(orderMatch[1]); const b=await body(req);
      const allowed=['assigned','accepted','in_progress','completed','cancelled','problem'];
      if (!allowed.includes(b.status)) return send(res,400,{error:'Invalid status.'});
      const o=db.prepare('SELECT * FROM orders WHERE id=?').get(id);
      if (!o) return send(res,404,{error:'Order not found.'});
      if (user.role==='worker' && o.worker_id!==user.id) return send(res,403,{error:'Not your order.'});
      createEvent(id,user.id,b.status,b.note||'');
      return send(res,200,{ok:true});
    }

    if (req.method === 'GET' && p === '/api/workers') {
      if (user.role!=='admin') return send(res,403,{error:'Admins only.'});
      return send(res,200,{workers:db.prepare(`SELECT id,name,email,phone,active,created_at FROM users WHERE role='worker' ORDER BY name`).all()});
    }

    if (req.method === 'POST' && p === '/api/orders/assign') {
      if (user.role!=='admin') return send(res,403,{error:'Admins only.'});
      const b=await body(req);
      const o=db.prepare('SELECT * FROM orders WHERE id=?').get(Number(b.orderId));
      const w=db.prepare("SELECT * FROM users WHERE id=? AND role='worker' AND active=1").get(Number(b.workerId));
      if (!o || !w) return send(res,404,{error:'Order or worker not found.'});
      db.prepare('UPDATE orders SET worker_id=? WHERE id=?').run(w.id,o.id);
      createEvent(o.id,user.id,'assigned',`Assigned to ${w.name}`);
      return send(res,200,{ok:true});
    }

    if (req.method === 'POST' && p === '/api/complaints') {
      if (user.role!=='customer') return send(res,403,{error:'Customers only.'});
      const b=await body(req);
      const o=db.prepare('SELECT * FROM orders WHERE id=? AND customer_id=?').get(Number(b.orderId),user.id);
      if (!o || !b.message) return send(res,400,{error:'Valid order and complaint message are required.'});
      const r=db.prepare('INSERT INTO complaints(order_id,customer_id,message) VALUES(?,?,?)').run(o.id,user.id,b.message);
      createEvent(o.id,user.id,'problem','Customer submitted a complaint');
      return send(res,201,{complaintId:Number(r.lastInsertRowid)});
    }

    if (req.method === 'GET' && p === '/api/complaints') {
      if (user.role==='customer') {
        return send(res,200,{complaints:db.prepare(`SELECT c.*,o.service FROM complaints c JOIN orders o ON o.id=c.order_id
          WHERE c.customer_id=? ORDER BY c.id DESC`).all(user.id)});
      }
      if (user.role!=='admin') return send(res,403,{error:'Not allowed.'});
      return send(res,200,{complaints:db.prepare(`SELECT c.*,o.service,u.name customer_name FROM complaints c
        JOIN orders o ON o.id=c.order_id JOIN users u ON u.id=c.customer_id ORDER BY c.id DESC`).all()});
    }

    if (req.method === 'POST' && p === '/api/ratings') {
      if (user.role!=='customer') return send(res,403,{error:'Customers only.'});
      const b=await body(req); const o=db.prepare('SELECT * FROM orders WHERE id=? AND customer_id=?').get(Number(b.orderId),user.id);
      if (!o || o.status!=='completed') return send(res,400,{error:'Only completed orders can be rated.'});
      const rating=Math.round(Number(b.rating));
      if (rating<1 || rating>5) return send(res,400,{error:'Rating must be 1 to 5.'});
      try {
        db.prepare('INSERT INTO ratings(order_id,customer_id,worker_id,rating,comment) VALUES(?,?,?,?,?)')
          .run(o.id,user.id,o.worker_id,rating,b.comment||'');
      } catch(e) { return send(res,409,{error:'This order has already been rated.'}); }
      return send(res,201,{ok:true});
    }

    if (req.method === 'GET' && p === '/api/stats') {
      if (user.role!=='admin') return send(res,403,{error:'Admins only.'});
      const total=db.prepare('SELECT COUNT(*) n FROM orders').get().n;
      const pending=db.prepare("SELECT COUNT(*) n FROM orders WHERE status IN ('pending','assigned','accepted','in_progress')").get().n;
      const completed=db.prepare("SELECT COUNT(*) n FROM orders WHERE status='completed'").get().n;
      const revenue=db.prepare("SELECT COALESCE(SUM(price),0) n FROM orders WHERE status='completed'").get().n;
      const workers=db.prepare("SELECT COUNT(*) n FROM users WHERE role='worker' AND active=1").get().n;
      const complaints=db.prepare("SELECT COUNT(*) n FROM complaints WHERE status!='resolved'").get().n;
      return send(res,200,{total,pending,completed,revenue,workers,complaints});
    }

    return send(res,404,{error:'Not found.'});
  } catch(e) {
    console.error(e);
    return send(res,500,{error:'Server error.'});
  }
}

function serveStatic(req,res) {
  let file = new URL(req.url, `http://${req.headers.host}`).pathname;
  if (file === '/') file='/index.html';
  const safe=path.normalize(file).replace(/^(\.\.[\/\\])+/, '');
  const full=path.join(__dirname,'public',safe);
  if (!full.startsWith(path.join(__dirname,'public'))) return send(res,403,{error:'Forbidden'});
  fs.readFile(full,(err,data)=>{
    if(err) return send(res,404,'Not found','text/plain');
    const ext=path.extname(full);
    const types={'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.webmanifest':'application/manifest+json','.svg':'image/svg+xml'};
    send(res,200,data,types[ext]||'application/octet-stream');
  });
}
http.createServer((req,res)=>{
  if(req.url.startsWith('/api/')) return api(req,res);
  serveStatic(req,res);
}).listen(PORT,()=>console.log(`Campus Assist running on http://localhost:${PORT}`));
