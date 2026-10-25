import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audience, brokerURL, exchange, revoke } from './client';
import { run, cleanup } from './lifecycle';

test('only HTTPS broker URLs without credentials or URL parameters are accepted', () => {
  for (const url of ['http://broker.test', 'https://user:pass@broker.test', 'https://broker.test?a=b', 'https://broker.test/#token']) {
    assert.throws(() => brokerURL(url));
  }
  assert.equal(audience(brokerURL('https://broker.test/prefix/')), 'https://broker.test/prefix');
});

test('exchange sends OIDC only to the broker, refuses redirects and validates result', async () => {
  const credential = { token: 'ghs_test', expires_at: new Date(Date.now()+3600_000).toISOString() };
  const request: typeof fetch = async (url, init) => {
    assert.equal(url, 'https://broker.test/v1/token');
    assert.equal(init?.method, 'POST');
    assert.equal(init?.redirect, 'error');
    assert.equal((init?.headers as Record<string,string>).Authorization, 'Bearer oidc');
    assert.equal(init?.body, undefined);
    return Response.json(credential);
  };
  assert.deepEqual(await exchange(brokerURL('https://broker.test'), 'oidc', request), credential);
});

test('exchange does not expose errors or accept expired/malformed credentials', async () => {
  const url = brokerURL('https://broker.test');
  await assert.rejects(exchange(url, 'oidc', async () => new Response('sensitive', {status:403})), /^Error: Broker returned HTTP 403$/);
  for (const data of [null, {}, {token:'ghs_test', expires_at:'2000-01-01'}, {token:'a\nb', expires_at:'2100-01-01'}]) {
    await assert.rejects(exchange(url, 'oidc', async () => Response.json(data)), /Invalid broker response/);
  }
});

test('cleanup revokes only at GitHub; expiry is idempotent and other failures fail cleanup', async () => {
  for (const status of [204,401,500]) {
    const request: typeof fetch = async (url, init) => {
      assert.equal(url, 'https://api.github.com/installation/token');
      assert.equal(init?.method, 'DELETE');
      assert.equal(init?.redirect, 'error');
      assert.equal((init?.headers as Record<string,string>).Authorization, 'Bearer ghs_test');
      return new Response(null, {status});
    };
    if (status === 500) await assert.rejects(revoke('ghs_test',request), /HTTP 500/);
    else await revoke('ghs_test',request);
  }
});

test('lifecycle masks and saves credentials before output, then revokes saved state', async () => {
  const calls: [string, unknown][] = [];
  let saved = '';
  const core = {
    getInput: () => 'https://broker.test/',
    getIDToken: async (value?: string) => { assert.equal(value,'https://broker.test'); return 'oidc'; },
    setSecret: (value: string) => { calls.push(['mask',value]); },
    saveState: (name: string,value: unknown) => { assert.equal(name,'token'); saved=String(value); calls.push(['save',value]); },
    setOutput: (name: string,value: unknown) => { calls.push([name,value]); },
    getState: () => saved,
    info: () => {},
  };
  const expires_at = new Date(Date.now()+3600_000).toISOString();
  await run(core, async () => Response.json({token:'ghs_test', expires_at}));
  assert.deepEqual(calls,[['mask','oidc'],['mask','ghs_test'],['save','ghs_test'],['token','ghs_test'],['expires-at',expires_at]]);
  await cleanup(core, async (url,init) => {
    assert.equal(url,'https://api.github.com/installation/token');
    assert.equal((init?.headers as Record<string,string>).Authorization,'Bearer ghs_test');
    return new Response(null,{status:204});
  });
  saved='';
  await cleanup(core, async () => { throw new Error('cleanup must not call GitHub without a token'); });
});
