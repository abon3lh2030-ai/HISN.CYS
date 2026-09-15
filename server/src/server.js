import { createServer } from 'node:http';
import { createHash, randomBytes, createCipheriv, createDecipheriv, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, extname, sep } from 'node:path';
import { createHISNServer } from './core.js';

const publicRoot = resolve(fileURLToPath(new URL('../../public/', import.meta.url)));
const core = createHISNServer();
const budgets = new Map();
const DAY = 86400_000;
const securityHeaders = {
  'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'no-referrer',
  'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
  'Strict-Transport-Security':'max-age=31536000; includeSubDomains'
};
class APIError extends Error { constructor(status, code) { super(code); this.status=status; this.code=code; } }
function json(res,status,value) { res.writeHead(status,{...securityHeaders,'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(value)); }
const hash = value => createHash('sha256').update(value).digest('hex');
function cookieKey() { const secret=process.env.HISN_API_ACCESS_TOKEN; if(!secret || secret.length<32) throw new APIError(503,'server_not_configured');return createHash('sha256').update('hisn-web-cookie-v1:'+secret).digest(); }
function equal(a,b) {const x=Buffer.from(a||''),y=Buffer.from(b||'');return x.length===y.length && timingSafeEqual(x,y);}
function encodeSession(session) { const iv=randomBytes(12);const cipher=createCipheriv('aes-256-gcm',cookieKey(),iv);return Buffer.concat([iv,cipher.update(JSON.stringify(session)),cipher.final(),cipher.getAuthTag()]).toString('base64url'); }
function sessionFrom(req) {
  const value=req.headers.cookie?.split(';').find(c=>c.trim().startsWith('hisn_session='))?.trim().slice(13);
  if(!value || value.length>2000) return null;
  try {const bytes=Buffer.from(value,'base64url');const dec=createDecipheriv('aes-256-gcm',cookieKey(),bytes.subarray(0,12));dec.setAuthTag(bytes.subarray(-16));const s=JSON.parse(Buffer.concat([dec.update(bytes.subarray(12,-16)),dec.final()]).toString());return s.expires>Date.now() && typeof s.csrf==='string'?s:null;} catch{return null;}
}
function setSession(req,res,session) { const secure=process.env.NODE_ENV==='production'||req.headers['x-forwarded-proto']==='https';res.setHeader('Set-Cookie',`hisn_session=${encodeSession(session)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000${secure?'; Secure':''}`); }
function makeSession(vault=null) {return {csrf:randomBytes(24).toString('hex'),vault,expires:Date.now()+30*DAY};}
async function body(req,max=12*1024*1024) {let n=0;const chunks=[];for await(const c of req){n+=c.length;if(n>max)throw new APIError(413,'payload_too_large');chunks.push(c);}try{return JSON.parse(Buffer.concat(chunks).toString());}catch{throw new APIError(400,'invalid_json');}}
function csrf(req,session) {
  if(!session||!equal(req.headers['x-hisn-csrf'],session.csrf))throw new APIError(403,'invalid_session');
  if(req.headers['sec-fetch-site']==='cross-site')throw new APIError(403,'invalid_origin');
  if(req.headers.origin){let origin;try{origin=new URL(req.headers.origin);}catch{throw new APIError(403,'invalid_origin');}if(origin.host!==req.headers.host)throw new APIError(403,'invalid_origin');}
}
function limit(req,name,max,window=60000) {
  const ip=req.headers['x-forwarded-for']?.split(',')[0]?.trim()||req.socket.remoteAddress;
  const key=hash(`${name}:${ip}`), now=Date.now();
  if(budgets.size>10000)for(const [k,b] of budgets)if(b.until<now)budgets.delete(k);
  const b=budgets.get(key);if(!b||b.until<now)budgets.set(key,{count:1,until:now+window});else if(++b.count>max)throw new APIError(429,'rate_limited');
}
export function validateVaultKey(value) {if(typeof value!=='string'||!/^hisn_[a-f0-9]{64}$/.test(value))throw new APIError(400,'invalid_vault_key');return value;}
function vaultFor(req,s) {const bearer=req.headers.authorization?.replace(/^Bearer\s+/i,'');return hash(validateVaultKey(bearer||s?.vault));}
export function validateRecord(r) {
  if(!r||typeof r.id!=='string'||! /^[a-f0-9-]{36}$/i.test(r.id)||!['message','link','phone','screenshot'].includes(r.scanTypeRaw))throw new APIError(400,'invalid_record');
  const date=new Date(r.date);if(!Number.isFinite(date.getTime())||typeof r.riskScore!=='number'||!Number.isFinite(r.riskScore)||!Array.isArray(r.signals)||!Array.isArray(r.recommendations))throw new APIError(400,'invalid_record');
  const score=Math.min(100,Math.max(0,Math.round(r.riskScore)));
  const record={id:r.id,date:date.toISOString(),scanTypeRaw:r.scanTypeRaw,contentPreview:String(r.contentPreview||'').slice(0,100).replace(/\d{4,}/g,'••••'),riskScore:score,riskLevelRaw:score<=25?'low':score<=50?'caution':score<=75?'high':'critical',signals:r.signals.slice(0,20),recommendations:r.recommendations.slice(0,8),sourceRaw:r.sourceRaw==='shortcut'?'shortcut':'manual'};
  if(JSON.stringify(record).length>20000)throw new APIError(400,'invalid_record');return record;
}
async function db(path,options={}) {
  const base=process.env.SUPABASE_URL, key=process.env.SUPABASE_SECRET_KEY;
  if(!base||!key)throw new APIError(503,'storage_not_configured');
  const response=await fetch(`${base.replace(/\/$/,'')}/rest/v1/${path}`,{...options,headers:{apikey:key,'Content-Type':'application/json',...options.headers},signal:AbortSignal.timeout(15000)});
  if(!response.ok){console.error('History storage error',response.status);throw new APIError(503,'storage_unavailable');}
  return response.status===204?null:response.text().then(t=>t?JSON.parse(t):null);
}
async function history(req,res,s) {
  const owner=vaultFor(req,s);limit(req,'history',60);
  if(req.method==='GET'){const [rows,removed]=await Promise.all([db(`scan_history?owner_hash=eq.${owner}&deleted_at=is.null&select=record&order=scanned_at.desc&limit=500`),db(`scan_history?owner_hash=eq.${owner}&deleted_at=not.is.null&select=id&order=deleted_at.desc&limit=500`)]);return json(res,200,{records:rows.map(x=>x.record),deletedIds:removed.map(x=>x.id)});}
  if(req.method==='POST'){
    const input=await body(req,2*1024*1024);if(!Array.isArray(input.records)||input.records.length<1||input.records.length>500)throw new APIError(400,'invalid_records');
    const valid=input.records.map(validateRecord);
    const removed=await db(`scan_history?owner_hash=eq.${owner}&deleted_at=not.is.null&select=id&limit=10000`);
    const deleted=new Set(removed.map(x=>x.id.toLowerCase()));
    const rows=valid.filter(r=>!deleted.has(r.id.toLowerCase())).map(r=>({id:r.id,owner_hash:owner,scanned_at:r.date,record:r}));
    if(!rows.length)return json(res,200,{saved:0});
    await db('scan_history?on_conflict=owner_hash,id',{method:'POST',headers:{Prefer:'resolution=merge-duplicates,return=minimal'},body:JSON.stringify(rows)});return json(res,200,{saved:rows.length});
  }
  if(req.method==='DELETE'){
    const input=await body(req,30000);const ids=input.ids||[input.id];if(!Array.isArray(ids)||!ids.length||ids.length>500||ids.some(id=>typeof id!=='string'||! /^[a-f0-9-]{36}$/i.test(id)))throw new APIError(400,'invalid_record');
    await db(`scan_history?owner_hash=eq.${owner}&id=in.(${ids.join(',')})`,{method:'PATCH',headers:{Prefer:'return=minimal'},body:JSON.stringify({deleted_at:new Date().toISOString()})});return json(res,200,{deleted:true});
  }
  throw new APIError(405,'method_not_allowed');
}
const webRoutes={'/api/chat':'/v1/ai/chat','/api/tools/ip-lookup':'/v1/tools/ip-lookup','/api/tools/dns-lookup':'/v1/tools/dns-lookup'};
export function createWebServer() {
  return createServer(async(req,res)=>{
    const url=new URL(req.url,'http://localhost');
    try{
      if(url.pathname==='/health')return json(res,200,{status:'ok',service:'hisn-secure-api',version:'2',web:true});
      if(url.pathname==='/api/session'&&req.method==='GET'){let s=sessionFrom(req);if(!s){s=makeSession();setSession(req,res,s);}return json(res,200,{csrf:s.csrf,connected:Boolean(s.vault),backend:'hisn-secure-api',version:'2'});}
      if(url.pathname.startsWith('/api/')){
        const s=sessionFrom(req);if(req.method!=='GET')csrf(req,s);
        if(url.pathname==='/api/vault/create'&&req.method==='POST'){limit(req,'vault',8);const key='hisn_'+randomBytes(32).toString('hex');await db('scan_history?select=id&limit=0');const next=makeSession(key);setSession(req,res,next);return json(res,200,{key,csrf:next.csrf,connected:true});}
        if(url.pathname==='/api/vault/connect'&&req.method==='POST'){limit(req,'vault',8);const input=await body(req,2000);const key=validateVaultKey(input.key);await db('scan_history?select=id&limit=0');const next=makeSession(key);setSession(req,res,next);return json(res,200,{csrf:next.csrf,connected:true});}
        if(url.pathname==='/api/vault/disconnect'&&req.method==='POST'){const next=makeSession();setSession(req,res,next);return json(res,200,{csrf:next.csrf,connected:false});}
        if(url.pathname==='/api/history')return await history(req,res,s);
        if(webRoutes[url.pathname]&&req.method==='POST'){
          limit(req,'web-ai',30,DAY);limit(req,'web-minute',10);
          req.headers.authorization='Bearer '+(process.env.HISN_API_ACCESS_TOKEN||'');req.headers['x-hisn-app-version']='web-1.0';req.url=webRoutes[url.pathname];return core.emit('request',req,res);
        }
        throw new APIError(404,'not_found');
      }
      if(url.pathname==='/v1/history')return await history(req,res,null);
      if(url.pathname.startsWith('/v1/'))return core.emit('request',req,res);
      if(!['GET','HEAD'].includes(req.method))throw new APIError(405,'method_not_allowed');
      const requested=url.pathname==='/'?'index.html':decodeURIComponent(url.pathname).replace(/^\//,'');
      const target=resolve(publicRoot,requested);if(!target.startsWith(publicRoot+sep))throw new APIError(404,'not_found');
      let data;try{data=await readFile(target);}catch{throw new APIError(404,'not_found');}
      const types={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.png':'image/png','.svg':'image/svg+xml','.json':'application/json'};
      res.writeHead(200,{...securityHeaders,'Content-Type':types[extname(target)]||'application/octet-stream','Cache-Control':'no-cache'});res.end(req.method==='HEAD'?undefined:data);
    }catch(error){const known=error instanceof APIError?error:new APIError(503,'service_unavailable');if(!res.headersSent)json(res,known.status,{code:known.code});else res.end();}
  });
}
if(process.argv[1]===fileURLToPath(import.meta.url)){const port=Number(process.env.PORT||10000);createWebServer().listen(port,'0.0.0.0',()=>console.log(`HISN web + shared API ready at http://localhost:${port}`));}
