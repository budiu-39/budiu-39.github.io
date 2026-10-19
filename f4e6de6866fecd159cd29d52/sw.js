const SCOPE=new URL('./',self.location).pathname,te=new TextEncoder();
const TYPES={html:'text/html; charset=utf-8',js:'text/javascript; charset=utf-8',mjs:'text/javascript; charset=utf-8',css:'text/css; charset=utf-8',json:'application/json; charset=utf-8',csv:'text/csv; charset=utf-8',txt:'text/plain; charset=utf-8',md:'text/plain; charset=utf-8',svg:'image/svg+xml',png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',webp:'image/webp',gif:'image/gif',mp4:'video/mp4',webm:'video/webm',glb:'model/gltf-binary',bin:'application/octet-stream',wasm:'application/wasm',woff2:'font/woff2'};
let keys=null;const plain=new Map();
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const loadKeys=()=>new Promise(res=>{const r=indexedDB.open('gate',1);r.onupgradeneeded=()=>r.result.createObjectStore('k');
  r.onsuccess=()=>{const q=r.result.transaction('k','readonly').objectStore('k').get('keys');q.onsuccess=()=>res(q.result||null);q.onerror=()=>res(null)};r.onerror=()=>res(null)});
self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('message',e=>{if(e.data==='reset'){keys=null;plain.clear()}});
self.addEventListener('fetch',e=>{const u=new URL(e.request.url);if(u.origin===location.origin&&u.pathname.startsWith(SCOPE+'v/'))e.respondWith(serve(u,e.request))});
function toGate(u,req){if(req.mode!=='navigate')return new Response('',{status:403});
  return Response.redirect(new URL(SCOPE+'?next='+encodeURIComponent(u.pathname.slice(SCOPE.length)+u.search),location.origin).href,302)}
async function serve(u,req){
  let p=decodeURIComponent(u.pathname.slice(SCOPE.length+2));if(p===''||p.endsWith('/'))p+='index.html';
  keys=keys||await loadKeys();if(!keys)return toGate(u,req);
  const name=hex(await crypto.subtle.sign('HMAC',keys.mac,te.encode(p))).slice(0,32);
  const r=await fetch(SCOPE+'x/'+name,{cache:'no-cache'});if(!r.ok)return new Response('Not found',{status:404});
  const tag=r.headers.get('etag')||r.headers.get('last-modified')||'';let pt;const hit=plain.get(name);
  if(hit&&tag&&hit.tag===tag){pt=hit.pt;r.body?.cancel()}else{
    const b=new Uint8Array(await r.arrayBuffer());
    try{pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b.slice(0,12)},keys.aes,b.slice(12))}catch(e){keys=null;return toGate(u,req)}
    if(pt.byteLength>1e6){plain.set(name,{tag,pt});while(plain.size>4)plain.delete(plain.keys().next().value)}}
  const h={'Content-Type':TYPES[p.split('.').pop().toLowerCase()]||'application/octet-stream','Accept-Ranges':'bytes','Cache-Control':'no-store'};
  const range=req.headers.get('range'),m=range&&/bytes=(\d*)-(\d*)/.exec(range);
  if(m){const n=pt.byteLength,s=m[1]?+m[1]:n-+m[2],t=m[1]&&m[2]?Math.min(+m[2],n-1):n-1;
    return new Response(pt.slice(s,t+1),{status:206,headers:{...h,'Content-Range':`bytes ${s}-${t}/${n}`}})}
  return new Response(pt,{headers:h})}
