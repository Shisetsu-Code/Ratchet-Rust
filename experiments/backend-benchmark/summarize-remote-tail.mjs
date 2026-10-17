import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
// Only constants from this allowlist may become report paths. Unknown paths
// cannot carry invitation tokens, percent-encoded secrets, or arbitrary suffixes.
const routeTemplates=[
 '/api','/api/v1/health','/api/v1/chats','/api/v1/sessions','/api/v1/sessions/current',
 '/api/v1/auth/logout','/api/v1/auth/password/login','/api/v1/auth/password/reauth',
 '/api/v1/auth/password/challenge','/api/v1/auth/portable-key/login/prepare',
 '/api/v1/auth/portable-key/login/complete','/api/v1/auth/portable-key/reauth/prepare',
 '/api/v1/auth/portable-key/reauth/complete','/api/v1/bootstrap/status',
 '/api/v1/bootstrap/portable-key/prepare','/api/v1/bootstrap/portable-key/complete',
 '/api/v1/invitations/:token/claim','/api/v1/invitations/:token',
 '/api/v1/chats/:chat_id','/api/v1/chats/:chat_id/realtime',
 '/api/v1/chats/:chat_id/sync','/api/v1/chats/:chat_id/messages',
 '/api/v1/chats/:chat_id/messages/batch','/api/v1/chats/:chat_id/messages/sender-sequence',
 '/api/v1/chats/:chat_id/messages/by-client-id/:client_message_id',
 '/api/v1/chats/:chat_id/receipts','/api/v1/chats/:chat_id/receipts/batch',
 '/api/v1/chats/:chat_id/wallpaper','/api/v1/sessions/:session_id','/api/v1/devices/:device_id',
];
const routes=routeTemplates.map(template=>[new RegExp('^'+template.replace(/:[a-z_]+/g,'[^/]+')+'/?$'),template]);
function reportPath(url){
 try{
  const path=new URL(url).pathname;
  return routes.find(([pattern])=>pattern.test(path))?.[1]??'/:unrecognized';
 }catch{return '/:unrecognized';}
}
// Wrangler emits pretty-printed, concatenated JSON objects, not JSONL.
export function parseTail(source){
let depth=0,quoted=false,escaped=false,start=0;
const events=[];
for(let i=0;i<source.length;i++){
 const char=source[i];
 if(quoted){if(escaped)escaped=false;else if(char==='\\')escaped=true;else if(char==='"')quoted=false;continue;}
 if(char==='"'){quoted=true;continue;}
 if(char==='{'){if(depth===0)start=i;depth++;}
 if(char==='}'&&--depth===0){
  const event=JSON.parse(source.slice(start,i+1));
  events.push({outcome:event.outcome,execution_model:event.executionModel,event_fields:Object.keys(event.event??{}),cpu_ms:event.cpuTime,wall_ms:event.wallTime,status:event.event?.response?.status,path:event.event?.request?.url?reportPath(event.event.request.url):undefined,exception_names:event.exceptions?.map(x=>x.name)});
 }
}
return events;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const events=parseTail(await readFile(process.argv[2]??'.wrangler/remote-perf-tail.jsonl','utf8'));
 const groups={};
 for(const event of events){const key=JSON.stringify([event.execution_model,event.event_fields,event.status??null,event.outcome]);(groups[key]??=[]).push(event);}
 const stats=values=>({count:values.length,mean:values.reduce((a,b)=>a+b,0)/values.length,max:Math.max(...values)});
 console.log(JSON.stringify({events_count:events.length,groups:Object.entries(groups).map(([kind,rows])=>({kind:JSON.parse(kind),cpu_ms:stats(rows.map(e=>e.cpu_ms??0)),wall_ms:stats(rows.map(e=>e.wall_ms??0))})),...(process.argv.includes('--events')&&!process.argv.includes('--summary')?{events}:{})},null,2));
}
