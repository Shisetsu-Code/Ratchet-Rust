import {test} from 'node:test';
import assert from 'node:assert/strict';
import {isIP} from 'node:net';
import {spawnSync} from 'node:child_process';
import * as fixtures from '../contracts/fixtures.mjs';

test('local contract files keep stable, distinct edge origins and reject remote injection', () => {
  assert.equal(typeof fixtures.contractOriginHeaders,'function');
  const headers=fixtures.contractOriginHeaders('auth.mjs');
  assert.equal(isIP(headers['CF-Connecting-IP']),6);
  assert.match(headers['CF-Connecting-IP'],/^2001:db8:/);
  assert.deepEqual(headers,fixtures.contractOriginHeaders('auth.mjs'));
  assert.notDeepEqual(headers,fixtures.contractOriginHeaders('owner.mjs'));
  assert.throws(()=>fixtures.contractOriginHeaders('auth.mjs','https://example.com'),/local/);
});

test('anonymous and signed-in contract requests use the same file origin across retries', async () => {
  const calls=[],original=globalThis.fetch;
  globalThis.fetch=async(url,options)=>{calls.push({url,options});return Response.json({ok:true});};
  try {
    await fixtures.api('/owner-console/prepare',{body:{owner_key_id:'synthetic'}});
    await fixtures.api('/auth/password/login',{cookie:'__Host-session=synthetic',body:{login_name:'synthetic'}});
    await fixtures.api('/owner-console/prepare',{body:{owner_key_id:'synthetic'}});
  } finally {globalThis.fetch=original;}
  assert.equal(isIP(calls[0].options.headers['CF-Connecting-IP']),6);
  for(const call of calls)assert.equal(call.options.headers['CF-Connecting-IP'],fixtures.edgeHeaders['CF-Connecting-IP']);
});

test('native console transport carries its parent origin and refuses other servers', () => {
  const script=`import json, runpy, urllib.request
module=runpy.run_path('tests/contracts/native-console.py', run_name='contract_origin_test')
address='2001:db8:1234:5678:90ab:cdef:1234:5678'
handler=module['LocalTestEdge']('http://localhost:8797',address)
request=handler.http_request(urllib.request.Request('http://localhost:8797/api/v1/owner-console/prepare'))
assert request.get_header('Cf-connecting-ip')==address
try:
 handler.http_request(urllib.request.Request('https://example.com/api/v1/owner-console/prepare'))
except ValueError:
 pass
else:
 raise AssertionError('synthetic edge headers must stay on the local test server')
print(json.dumps({'edge_address':request.get_header('Cf-connecting-ip')}))
`;
  const result=spawnSync(process.env.RATCHET_PYTHON??'python',['-c',script],{encoding:'utf8',windowsHide:true});
  assert.equal(result.status,0,result.stderr);
  assert.equal(JSON.parse(result.stdout).edge_address,'2001:db8:1234:5678:90ab:cdef:1234:5678');
});
