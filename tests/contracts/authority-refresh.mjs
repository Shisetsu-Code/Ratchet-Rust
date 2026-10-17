import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import WebSocket from 'ws';
import {base,fixture,localSql,api,edgeHeaders} from './fixtures.mjs';

test('revoking one session keeps unrelated passive sockets open throughout grant refresh',{timeout:30000},async()=>{
  const actor=await fixture(),chat=randomUUID(),now=new Date().toISOString();
  await localSql(`INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('${chat}','${actor.workspace_id}','${actor.user_id}','${actor.user_id}','${now}');`);
  const peers=[];
  const open=async account=>{
    const socket=new WebSocket(base.replace(/^http/,'ws')+`/api/v1/chats/${chat}/realtime`,{closeTimeout:300,headers:{Cookie:account.cookie,Origin:base,...edgeHeaders}});
    const peer={socket,events:[],closed:null};peers.push(peer);
    socket.on('close',(code,reason)=>{peer.closed={code,reason:reason.toString()};});
    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(new Error('Realtime ready timeout')),5000);
      socket.on('message',raw=>{const event=JSON.parse(raw.toString());peer.events.push(event);if(event.type==='realtime.ready'){clearTimeout(timer);resolve();}});
      socket.once('error',error=>{clearTimeout(timer);reject(error);});
    });
    return peer;
  };
  try{
    const revoked=await open(actor),readers=[];
    // Multiple passive peers exercise close-event interleaving while release
    // refreshes grants via D1. Four sockets per device remain within the cap.
    for(let user=0;user<4;user++){
      const reader=await fixture();
      await localSql(`UPDATE users SET role='CUSTOMER' WHERE user_id='${reader.user_id}'; INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES('${actor.workspace_id}','${reader.user_id}','CUSTOMER','ACTIVE','${now}'); INSERT INTO chat_participants(chat_id,user_id,participant_role,joined_at) VALUES('${chat}','${reader.user_id}','CUSTOMER','${now}');`);
      for(let tab=0;tab<4;tab++)readers.push(await open(reader));
    }
    const response=await api(`/sessions/${actor.session_id}`,{cookie:actor.cookie,method:'DELETE'});
    assert.equal(response.status,204,JSON.stringify(response.value));
    const deadline=Date.now()+3000;
    while(!revoked.closed&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,10));
    assert.equal(revoked.closed?.code,4001);
    // A ping after completed refresh proves each surviving connection remains
    // usable; no reconnect may conceal a wrongful close of a valid reader.
    for(const peer of readers)if(peer.socket.readyState===WebSocket.OPEN)peer.socket.send(JSON.stringify({type:'ping'}));
    while(readers.some(peer=>!peer.closed&&!peer.events.some(e=>e.type==='pong'))&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,10));
    for(const peer of readers){
      assert.equal(peer.closed,null,JSON.stringify(peer.closed));
      assert.equal(peer.socket.readyState,WebSocket.OPEN);
      assert.ok(peer.events.some(event=>event.type==='pong'));
    }
  }finally{for(const peer of peers)peer.socket.terminate();}
});
