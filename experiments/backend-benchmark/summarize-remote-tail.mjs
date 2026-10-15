import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
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
  events.push({outcome:event.outcome,execution_model:event.executionModel,event_fields:Object.keys(event.event??{}),cpu_ms:event.cpuTime,wall_ms:event.wallTime,status:event.event?.response?.status,path:event.event?.request?.url?new URL(event.event.request.url).pathname.replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi,'ID'):undefined,exception_names:event.exceptions?.map(x=>x.name)});
 }
}
return events;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const events=parseTail(await readFile(process.argv[2]??'.wrangler/remote-perf-tail.jsonl','utf8'));
 const groups={};
 for(const event of events){const key=JSON.stringify([event.execution_model,event.event_fields,event.status??null,event.outcome]);(groups[key]??=[]).push(event);}
 const stats=values=>({count:values.length,mean:values.reduce((a,b)=>a+b,0)/values.length,max:Math.max(...values)});
 console.log(JSON.stringify({events_count:events.length,groups:Object.entries(groups).map(([kind,rows])=>({kind:JSON.parse(kind),cpu_ms:stats(rows.map(e=>e.cpu_ms??0)),wall_ms:stats(rows.map(e=>e.wall_ms??0))})),...(process.argv.includes('--summary')?{}:{events})},null,2));
}
