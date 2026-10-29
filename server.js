'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 3000);
const sessions = new Map();
const DEFAULT_SERVICES = [
  ['Parcel Pickup',1500],['Printing / Photocopy',1500],['Assignment / Document Drop-off',1500],
  ['Queue as a Service',3999],['Food / Grocery Run',1500],['General Campus Errand',1500]
];

function send(res, status, data, type='application/json') {
  res.writeHead(status, {'Content-Type':type, 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff'});
  res.end(type === 'application/json' ? JSON.stringify(data) : data);
}
function hashPassword(p) {
  const salt=crypto.randomBytes(16).toString('hex');
  const iterations=210000;
  const derived=crypto.pbkdf2Sync(String(p),salt,iterations,32,'sha256').toString('hex');
  return `pbkdf2$${iterations}$${salt}$${derived}`;
}
function verifyPassword(password, stored) {
  if (typeof stored !== 'string') return false;
  if (stored.startsWith('pbkdf2$')) {
    const [,iterationsText,salt,expected]=stored.split('$');
    const iterations=Number(iterationsText);
    if (!Number.isInteger(iterations)||iterations<100000||iterations>1000000||!salt||!expected) return false;
    const actual=crypto.pbkdf2Sync(String(password),salt,iterations,32,'sha256').toString('hex');
    return actual.length===expected.length && crypto.timingSafeEqual(Buffer.from(actual),Buffer.from(expected));
  }
  // Legacy SQLite accounts used SHA-256; accept once, then upgrade the hash at login.
  const actual=crypto.createHash('sha256').update(String(password)).digest('hex');
  return actual.length===stored.length && crypto.timingSafeEqual(Buffer.from(actual),Buffer.from(stored));
}
function token() { return crypto.randomBytes(32).toString('hex'); }
function supabaseConfig() {
  const base = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!base || !key) throw new Error('Supabase is not configured. Check SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in Render.');
  return {base:base.replace(/\/$/,''), key, bucket:process.env.SUPABASE_STORAGE_BUCKET || 'uni-ease-orders'};
}
function readBody(req, maxBytes=14*1024*1024) {
  return new Promise((resolve,reject)=>{
    let data='', size=0, done=false;
    req.on('data', chunk => {
      if (done) return;
      size += chunk.length;
      if (size > maxBytes) { done=true; reject(Object.assign(new Error('Request too large. Files must be 10 MB or smaller.'),{status:413})); req.resume(); return; }
      data += chunk;
    });
    req.on('end',()=>{if(done)return; try{resolve(data?JSON.parse(data):{})}catch{reject(Object.assign(new Error('Invalid JSON request.'),{status:400}))}});
    req.on('error',e=>{if(!done)reject(e)});
  });
}
function queryValue(v) { return encodeURIComponent(String(v)); }
async function table(name, query='', {method='GET', body, prefer='return=representation'}={}) {
  const cfg=supabaseConfig();
  const url=`${cfg.base}/rest/v1/${name}${query ? `?${query}` : ''}`;
  const headers={Authorization:`Bearer ${cfg.key}`, apikey:cfg.key, Accept:'application/json', Prefer:prefer};
  if (body !== undefined) headers['Content-Type']='application/json';
  const response=await fetch(url,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
  const raw=await response.text(); let data;
  try { data=raw?JSON.parse(raw):[] } catch { data={message:raw} }
  if (!response.ok) {
    console.error(`Supabase ${method} ${name} failed (${response.status}):`, data);
    const err=new Error(data.message || data.details || data.hint || `Database request failed (${response.status}).`);
    err.status=response.status; throw err;
  }
  return data;
}
async function getById(name,id) {
  const rows=await table(name,`id=eq.${queryValue(id)}&select=*&limit=1`);
  return rows[0] || null;
}
async function getUserByEmail(email) {
  const rows=await table('users',`email=eq.${queryValue(email.trim().toLowerCase())}&select=*&limit=1`);
  return rows[0] || null;
}
function safeUser(u) { return {id:Number(u.id),name:u.name,email:u.email,role:u.role,phone:u.phone||''}; }
async function currentUser(req) {
  const t=req.headers.authorization?.replace(/^Bearer\s+/i,'');
  const id=sessions.get(t);
  if (!id) return null;
  const u=await getById('users',id);
  if (!u || u.active === false) { sessions.delete(t); return null; }
  return u;
}
function allowed(user, roles) { return user && roles.includes(user.role); }
async function createEvent(orderId, actorId, status, note='') {
  await table('order_events','',{method:'POST',body:{order_id:Number(orderId),actor_id:actorId?Number(actorId):null,status,note}});
  await table('orders',`id=eq.${queryValue(orderId)}`,{method:'PATCH',body:{status,updated_at:new Date().toISOString()}});
}
async function getOrderForUser(orderId,user) {
  const o=await getById('orders',orderId);
  if (!o) return {status:404,error:'Order not found.'};
  const customerId=Number(o.customer_id), workerId=o.worker_id==null?null:Number(o.worker_id);
  if (user.role==='admin' || (user.role==='customer' && customerId===Number(user.id)) || (user.role==='worker' && workerId===Number(user.id))) return {order:o};
  return {status:403,error:'You do not have access to this order conversation.'};
}
async function signedFileUrl(filePath) {
  const cfg=supabaseConfig();
  const encoded=filePath.split('/').map(encodeURIComponent).join('/');
  const r=await fetch(`${cfg.base}/storage/v1/object/sign/${encodeURIComponent(cfg.bucket)}/${encoded}`,{
    method:'POST',headers:{Authorization:`Bearer ${cfg.key}`,apikey:cfg.key,'Content-Type':'application/json'},body:JSON.stringify({expiresIn:300})
  });
  const d=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(d.message||d.error||'Could not create a secure file link.');
  const signed=d.signedURL||d.signedUrl;
  if(!signed) throw new Error('Storage did not return a secure file link.');
  return signed.startsWith('http')?signed:`${cfg.base}/storage/v1${signed}`;
}
async function uploadFile(orderId,file) {
  const allowedTypes=new Set(['image/jpeg','image/png','image/webp','image/gif','video/mp4','video/webm','application/pdf','text/plain','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document']);
  const mimeType=String(file.type||'application/octet-stream');
  if(!allowedTypes.has(mimeType)) throw Object.assign(new Error('This file type is not allowed. Send an image, video, PDF, TXT, or Word document.'),{status:400});
  const fileName=String(file.name||'attachment').replace(/[^a-zA-Z0-9._ -]/g,'_').slice(0,120);
  const encoded=String(file.data||'').replace(/^data:[^,]*;base64,/,'');
  const buffer=Buffer.from(encoded,'base64');
  if(!buffer.length || buffer.length>10*1024*1024) throw Object.assign(new Error('Each file must be 10 MB or smaller.'),{status:413});
  const cfg=supabaseConfig();
  const objectName=`orders/${orderId}/${crypto.randomUUID()}-${fileName.replace(/\s+/g,'_')}`;
  const keyPath=objectName.split('/').map(encodeURIComponent).join('/');
  const r=await fetch(`${cfg.base}/storage/v1/object/${encodeURIComponent(cfg.bucket)}/${keyPath}`,{
    method:'POST',headers:{Authorization:`Bearer ${cfg.key}`,apikey:cfg.key,'Content-Type':mimeType,'x-upsert':'false'},body:buffer
  });
  const d=await r.json().catch(()=>({}));
  if(!r.ok) { console.error('Storage upload failed:',r.status,d); throw Object.assign(new Error('File upload failed. Check that the private uni-ease-orders bucket exists and allows files up to 10 MB.'),{status:502}); }
  return {filePath:objectName,fileName,mimeType,fileSize:buffer.length};
}
async function api(req,res) {
  const url=new URL(req.url,`http://${req.headers.host||'localhost'}`); const p=url.pathname;
  try {
    if(req.method==='GET' && p==='/api/health') {
      // A live DB request means the endpoint verifies actual Supabase connectivity.
      await table('uni_ease_service_prices','select=name&limit=1');
      return send(res,200,{ok:true,database:'connected'});
    }
    if(req.method==='POST' && p==='/api/signup') {
      const b=await readBody(req);
      if(!b.name||!b.email||!b.password) return send(res,400,{error:'Name, email and password are required.'});
      if(String(b.password).length<6) return send(res,400,{error:'Password must be at least 8 characters.'});
      const email=String(b.email).trim().toLowerCase();
      if(await getUserByEmail(email)) return send(res,409,{error:'That email is already registered.'});
      const rows=await table('users','',{method:'POST',body:{name:String(b.name).trim(),email,password_hash:hashPassword(b.password),role:'customer',phone:String(b.phone||''),active:true}});
      const u=rows[0]; if(!u) throw new Error('Account was not returned after creation.');
      const t=token(); sessions.set(t,Number(u.id)); return send(res,201,{token:t,user:safeUser(u)});
    }
    if(req.method==='POST' && p==='/api/login') {
      const b=await readBody(req); const u=await getUserByEmail(String(b.email||''));
      if(!u || u.active===false || !verifyPassword(b.password||'',u.password_hash)) return send(res,401,{error:'Invalid login details.'});
      if (!String(u.password_hash).startsWith('pbkdf2$')) {
        const upgraded=hashPassword(b.password||'');
        await table('users',`id=eq.${queryValue(u.id)}`,{method:'PATCH',body:{password_hash:upgraded}});
      }
      const t=token(); sessions.set(t,Number(u.id)); return send(res,200,{token:t,user:safeUser(u)});
    }
    if(req.method==='POST' && p==='/api/logout') {
      const t=req.headers.authorization?.replace(/^Bearer\s+/i,''); if(t) sessions.delete(t); return send(res,200,{ok:true});
    }
    const user=await currentUser(req);
    if(!user) return send(res,401,{error:'Please log in.'});
    if(req.method==='GET' && p==='/api/me') return send(res,200,{user:safeUser(user)});
    if(req.method==='POST' && p==='/api/change-password') {
      const b=await readBody(req);
      if(!b.currentPassword||!b.newPassword||String(b.newPassword).length<8) return send(res,400,{error:'Enter your current password and a new password of at least 8 characters.'});
      const fresh=await getById('users',user.id);
      if(!fresh||!verifyPassword(b.currentPassword,fresh.password_hash)) return send(res,401,{error:'Current password is incorrect.'});
      await table('users',`id=eq.${queryValue(user.id)}`,{method:'PATCH',body:{password_hash:hashPassword(b.newPassword)}});
      return send(res,200,{ok:true,message:'Password changed. Use the new password next time you log in.'});
    }

    if(req.method==='GET' && p==='/api/services') {
      let rows=await table('uni_ease_service_prices','select=name,base,updated_at&order=name.asc');
      if(!rows.length) rows=DEFAULT_SERVICES.map(([name,base])=>({name,base}));
      return send(res,200,{services:rows.map(r=>({id:r.name,name:r.name,base:Number(r.base),updated_at:r.updated_at||null}))});
    }
    const priceMatch=p.match(/^\/api\/services\/(.+)$/);
    if(priceMatch && req.method==='PATCH') {
      if(user.role!=='admin') return send(res,403,{error:'Admins only.'});
      const name=decodeURIComponent(priceMatch[1]); const b=await readBody(req); const base=Number(b.base);
      if(!Number.isSafeInteger(base)||base<0||base>100000000) return send(res,400,{error:'Enter a valid non-negative price.'});
      const rows=await table('uni_ease_service_prices',`name=eq.${queryValue(name)}`,{method:'PATCH',body:{base,updated_at:new Date().toISOString()}});
      if(!rows.length) return send(res,404,{error:'Service price not found.'});
      return send(res,200,{service:rows[0]});
    }

    if(req.method==='POST' && p==='/api/orders') {
      if(user.role!=='customer') return send(res,403,{error:'Only customers can create orders.'});
      const b=await readBody(req);
      if(!b.service||!b.description||!b.delivery) return send(res,400,{error:'Service, description and delivery location are required.'});
      const priceRows=await table('uni_ease_service_prices',`name=eq.${queryValue(b.service)}&select=name,base&limit=1`);
      if(!priceRows.length) return send(res,400,{error:'Choose a valid service.'});
      const rows=await table('orders','',{method:'POST',body:{customer_id:Number(user.id),worker_id:null,service:String(b.service),description:String(b.description).trim(),pickup:String(b.pickup||''),delivery:String(b.delivery).trim(),price:Number(priceRows[0].base),status:'pending'}});
      const order=rows[0]; if(!order) throw new Error('Order was not returned after creation.');
      await createEvent(order.id,user.id,'pending','Order created');
      return send(res,201,{orderId:Number(order.id)});
    }
    if(req.method==='GET' && p==='/api/orders') {
      let rows=await table('orders','select=*&order=id.desc');
      if(user.role==='customer') rows=rows.filter(o=>Number(o.customer_id)===Number(user.id));
      else if(user.role==='worker') rows=rows.filter(o=>(o.worker_id!=null&&Number(o.worker_id)===Number(user.id))||(o.worker_id==null&&o.status==='pending'));
      const userIds=[...new Set(rows.flatMap(o=>[o.customer_id,o.worker_id].filter(x=>x!=null).map(Number)))];
      const people=new Map();
      for(const id of userIds){const u=await getById('users',id);if(u)people.set(id,u);}
      rows=rows.map(o=>({...o,customer_name:people.get(Number(o.customer_id))?.name||'',customer_phone:people.get(Number(o.customer_id))?.phone||'',worker_name:people.get(Number(o.worker_id))?.name||''}));
      return send(res,200,{orders:rows});
    }
    const orderMatch=p.match(/^\/api\/orders\/(\d+)(?:\/(accept|status|messages))?$/);
    if(orderMatch && req.method==='GET' && !orderMatch[2]) {
      const id=Number(orderMatch[1]); const access=await getOrderForUser(id,user);
      if(!access.order) return send(res,access.status,{error:access.error});
      const o=access.order; const customer=await getById('users',o.customer_id); const worker=o.worker_id?await getById('users',o.worker_id):null;
      const events=await table('order_events',`order_id=eq.${queryValue(id)}&select=*&order=id.asc`);
      const namedEvents=[]; for(const e of events){const actor=e.actor_id?await getById('users',e.actor_id):null; namedEvents.push({...e,actor_name:actor?.name||''});}
      return send(res,200,{order:{...o,customer_name:customer?.name||'',customer_phone:customer?.phone||'',worker_name:worker?.name||''},events:namedEvents});
    }
    if(orderMatch && req.method==='POST' && orderMatch[2]==='accept') {
      if(user.role!=='worker') return send(res,403,{error:'Workers only.'});
      const id=Number(orderMatch[1]); const o=await getById('orders',id);
      if(!o || (o.worker_id!=null&&Number(o.worker_id)!==Number(user.id)) || o.status!=='pending') return send(res,404,{error:'Order unavailable.'});
      await table('orders',`id=eq.${queryValue(id)}`,{method:'PATCH',body:{worker_id:Number(user.id)}});
      await createEvent(id,user.id,'accepted','Worker accepted the order'); return send(res,200,{ok:true});
    }
    if(orderMatch && req.method==='POST' && orderMatch[2]==='status') {
      if(!['worker','admin'].includes(user.role)) return send(res,403,{error:'Not allowed.'});
      const id=Number(orderMatch[1]); const b=await readBody(req); const allowedStatus=['assigned','accepted','in_progress','completed','cancelled','problem'];
      if(!allowedStatus.includes(b.status)) return send(res,400,{error:'Invalid status.'});
      const o=await getById('orders',id); if(!o) return send(res,404,{error:'Order not found.'});
      if(user.role==='worker'&&Number(o.worker_id)!==Number(user.id)) return send(res,403,{error:'Not your order.'});
      await createEvent(id,user.id,b.status,String(b.note||'')); return send(res,200,{ok:true});
    }
    if(orderMatch && orderMatch[2]==='messages') {
      const id=Number(orderMatch[1]); const access=await getOrderForUser(id,user);
      if(!access.order) return send(res,access.status,{error:access.error});
      if(req.method==='GET') {
        const rows=await table('uni_ease_order_messages',`order_id=eq.${queryValue(id)}&select=*&order=id.asc`);
        const messages=[];
        for(const row of rows){const sender=await getById('users',row.sender_id);if(!sender)continue;let fileUrl='';if(row.file_path){try{fileUrl=await signedFileUrl(row.file_path)}catch(e){console.error('Signed URL error:',e.message)}}messages.push({...row,sender_name:sender.name,sender_role:sender.role,file_url:fileUrl});}
        return send(res,200,{messages});
      }
      if(req.method==='POST') {
        if(user.role==='worker'&&Number(access.order.worker_id)!==Number(user.id)) return send(res,403,{error:'Only the assigned worker can message this order.'});
        if(user.role==='customer'&&Number(access.order.customer_id)!==Number(user.id)) return send(res,403,{error:'Not your order.'});
        const b=await readBody(req); const message=String(b.message||'').trim().slice(0,2000); let file={filePath:'',fileName:'',mimeType:'',fileSize:0};
        if(b.file&&b.file.data){const up=await uploadFile(id,b.file);file={filePath:up.filePath,fileName:up.fileName,mimeType:up.mimeType,fileSize:up.fileSize};}
        if(!message&&!file.filePath) return send(res,400,{error:'Write a message or attach a file.'});
        const rows=await table('uni_ease_order_messages','',{method:'POST',body:{order_id:id,order_ref:String(id),sender_id:Number(user.id),message,file_path:file.filePath,file_name:file.fileName,mime_type:file.mimeType,file_size:file.fileSize}});
        return send(res,201,{ok:true,messageId:rows[0]?.id||null});
      }
    }

    if(req.method==='GET' && p==='/api/workers') {
      if(user.role!=='admin') return send(res,403,{error:'Admins only.'});
      const workers=await table('users','role=eq.worker&select=id,name,email,phone,active,created_at&order=name.asc');
      return send(res,200,{workers});
    }
    if(req.method==='POST' && p==='/api/orders/assign') {
      if(user.role!=='admin') return send(res,403,{error:'Admins only.'});
      const b=await readBody(req); const o=await getById('orders',Number(b.orderId)); const w=await getById('users',Number(b.workerId));
      if(!o||!w||w.role!=='worker'||w.active===false) return send(res,404,{error:'Order or worker not found.'});
      await table('orders',`id=eq.${queryValue(o.id)}`,{method:'PATCH',body:{worker_id:Number(w.id)}});
      await createEvent(o.id,user.id,'assigned',`Assigned to ${w.name}`); return send(res,200,{ok:true});
    }
    if(req.method==='POST' && p==='/api/complaints') {
      if(user.role!=='customer') return send(res,403,{error:'Customers only.'});
      const b=await readBody(req); const o=await getById('orders',Number(b.orderId));
      if(!o||Number(o.customer_id)!==Number(user.id)||!String(b.message||'').trim()) return send(res,400,{error:'Valid order and complaint message are required.'});
      const rows=await table('complaints','',{method:'POST',body:{order_id:Number(o.id),customer_id:Number(user.id),message:String(b.message).trim()}});
      await createEvent(o.id,user.id,'problem','Customer submitted a complaint'); return send(res,201,{complaintId:Number(rows[0]?.id)});
    }
    if(req.method==='GET' && p==='/api/complaints') {
      let rows=await table('complaints','select=*&order=id.desc');
      if(user.role==='customer') rows=rows.filter(c=>Number(c.customer_id)===Number(user.id));
      else if(user.role!=='admin') return send(res,403,{error:'Not allowed.'});
      for(const c of rows){const o=await getById('orders',c.order_id);const customer=await getById('users',c.customer_id);c.service=o?.service||'';c.customer_name=customer?.name||'';}
      return send(res,200,{complaints:rows});
    }
    const resolveMatch=p.match(/^\/api\/complaints\/(\d+)\/resolve$/);
    if(resolveMatch&&req.method==='POST') {
      if(user.role!=='admin') return send(res,403,{error:'Admins only.'});
      const rows=await table('complaints',`id=eq.${queryValue(resolveMatch[1])}`,{method:'PATCH',body:{status:'resolved'}});
      if(!rows.length) return send(res,404,{error:'Complaint not found.'});
      return send(res,200,{message:'Complaint marked as resolved.'});
    }
    if(req.method==='POST' && p==='/api/ratings') {
      if(user.role!=='customer') return send(res,403,{error:'Customers only.'});
      const b=await readBody(req); const o=await getById('orders',Number(b.orderId));
      if(!o||Number(o.customer_id)!==Number(user.id)||o.status!=='completed') return send(res,400,{error:'Only your completed orders can be rated.'});
      const rating=Math.round(Number(b.rating)); if(rating<1||rating>5) return send(res,400,{error:'Rating must be 1 to 5.'});
      try { await table('ratings','',{method:'POST',body:{order_id:Number(o.id),customer_id:Number(user.id),worker_id:o.worker_id?Number(o.worker_id):null,rating,comment:String(b.comment||'')}}); }
      catch(e){if(e.status===409) return send(res,409,{error:'This order has already been rated.'});throw e;}
      return send(res,201,{ok:true});
    }
    if(req.method==='GET' && p==='/api/stats') {
      if(user.role!=='admin') return send(res,403,{error:'Admins only.'});
      const [orders,workers,complaints]=await Promise.all([table('orders','select=id,price,status'),table('users','role=eq.worker&active=eq.true&select=id'),table('complaints','select=id,status')]);
      return send(res,200,{total:orders.length,pending:orders.filter(o=>['pending','assigned','accepted','in_progress'].includes(o.status)).length,completed:orders.filter(o=>o.status==='completed').length,revenue:orders.filter(o=>o.status==='completed').reduce((s,o)=>s+Number(o.price||0),0),workers:workers.length,complaints:complaints.filter(c=>c.status!=='resolved').length});
    }
    return send(res,404,{error:'Not found.'});
  } catch(e) {
    console.error('API error:',e.message);
    return send(res,e.status&&e.status>=400&&e.status<600?e.status:500,{error:e.status===413||e.status===400?e.message:(e.status===401?'Please log in.':'Request failed. Please check the server configuration and try again.')});
  }
}
function serveStatic(req,res) {
  let pathname;
  try { pathname=decodeURIComponent(new URL(req.url,`http://${req.headers.host||'localhost'}`).pathname); } catch { return send(res,400,{error:'Invalid path.'}); }
  if(pathname==='/') pathname='/index.html';
  const root=path.resolve(__dirname,'public'); const full=path.resolve(root,'.'+pathname);
  if(full!==root&&!full.startsWith(root+path.sep)) return send(res,403,{error:'Forbidden.'});
  fs.readFile(full,(err,data)=>{
    if(err) return send(res,404,'Not found','text/plain');
    const ext=path.extname(full); const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json','.webmanifest':'application/manifest+json','.svg':'image/svg+xml'};
    send(res,200,data,types[ext]||'application/octet-stream');
  });
}
http.createServer((req,res)=>req.url.startsWith('/api/')?api(req,res):serveStatic(req,res)).listen(PORT,()=>console.log(`Uni Ease server listening on port ${PORT}`));
