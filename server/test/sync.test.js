import test from 'node:test';
import assert from 'node:assert/strict';
import {createWebServer} from '../src/server.js';
import {analyze} from '../../public/security.js';

test('cookie pairing and iOS bearer share isolated history using a LOCAL mocked database',async()=>{
  process.env.HISN_API_ACCESS_TOKEN='b'.repeat(64);
  process.env.SUPABASE_URL='https://local-db.invalid';
  process.env.SUPABASE_SECRET_KEY='test-only-key';
  process.env.GEMINI_API_KEY='local-test-only';
  const realFetch=globalThis.fetch,rows=[];
  let geminiCalls=0;
  globalThis.fetch=async(url,options={})=>{
    if(String(url).startsWith('https://generativelanguage.googleapis.com/')){
      geminiCalls++;
      if(geminiCalls===1)return Response.json({error:{status:'INTERNAL'}},{status:500});
      assert.ok(String(url).includes('gemini-3.8-flash'));
      const input=JSON.parse(options.body);assert.equal(input.contents.at(-1).parts[1].inlineData.mimeType,'image/png');
      return Response.json({candidates:[{content:{parts:[{text:'رد محلي تجريبي'}]}}]});
    }
    if(!String(url).startsWith('https://local-db.invalid/'))return realFetch(url,options);
    if(String(url).includes('/ai_operations'))return new Response(null,{status:204});
    const u=new URL(url),owner=u.searchParams.get('owner_hash')?.slice(3);
    if(options.method==='POST'){
      for(const row of JSON.parse(options.body)){const existing=rows.find(x=>x.owner_hash===row.owner_hash&&x.id===row.id);if(existing)Object.assign(existing,row);else rows.push({...row,deleted_at:null});}
      return new Response(null,{status:204});
    }
    if(options.method==='PATCH'){const ids=u.searchParams.get('id').slice(4,-1).split(',');for(const row of rows)if(row.owner_hash===owner&&ids.includes(row.id))row.deleted_at=JSON.parse(options.body).deleted_at;return new Response(null,{status:204});}
    if(u.searchParams.get('limit')==='0')return Response.json([]);
    const filtered=rows.filter(r=>r.owner_hash===owner&&(u.searchParams.get('deleted_at')==='is.null'?!r.deleted_at:!!r.deleted_at));
    return Response.json(filtered.map(r=>u.searchParams.get('select')==='id'?{id:r.id}:{record:r.record}));
  };
  const server=createWebServer();await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;
  try{
    const sr=await realFetch(base+'/api/session');let cookie=sr.headers.get('set-cookie').split(';')[0],s=await sr.json();
    const web=async(path,payload,method=payload?'POST':'GET')=>{const r=await realFetch(base+path,{method,headers:{cookie,'content-type':'application/json','x-hisn-csrf':s.csrf},body:payload?JSON.stringify(payload):undefined});const d=await r.json();assert.equal(r.status,200,JSON.stringify(d));if(r.headers.get('set-cookie'))cookie=r.headers.get('set-cookie').split(';')[0];if(d.csrf)s.csrf=d.csrf;return d;};
    const vault=await web('/api/vault/create',{});assert.match(vault.key,/^hisn_[a-f0-9]{64}$/);
    const native=async(method,payload,key=vault.key)=>{const r=await realFetch(base+'/v1/history',{method,headers:{authorization:'Bearer '+key,'content-type':'application/json'},body:payload?JSON.stringify(payload):undefined});assert.equal(r.status,200);return r.json();};
    const one={...analyze('local QA web'),contentPreview:'local web'},two={...analyze('local QA iOS'),contentPreview:'local iOS'};
    await web('/api/history',{records:[one]});assert.equal((await native('GET')).records.length,1);
    await native('POST',{records:[two]});assert.equal((await web('/api/history')).records.length,2);
    assert.equal((await native('GET',null,'hisn_'+'f'.repeat(64))).records.length,0);
    const current=await web('/api/session');assert.equal(current.connected,true);assert.equal(current.key,undefined);assert.equal(current.vault,undefined);
    await native('DELETE',{ids:[one.id,two.id]});assert.equal((await web('/api/history')).records.length,0);
    await native('POST',{records:[one]});assert.equal((await native('GET')).records.length,0);
    const ai=await web('/api/chat',{messages:[{role:'user',text:'صورة تجريبية'}],image:{mimeType:'image/png',data:'AQID'}});
    assert.equal(ai.text,'رد محلي تجريبي');assert.equal(geminiCalls,2);
    await web('/api/vault/disconnect',{});assert.equal((await web('/api/session')).connected,false);
  }finally{server.close();globalThis.fetch=realFetch;}
});
