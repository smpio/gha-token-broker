import type * as toolkit from '@actions/core';
import { audience, brokerURL, exchange, revoke } from './client';

type Core = Pick<typeof toolkit, 'getInput' | 'getIDToken' | 'setSecret' | 'saveState' | 'setOutput' | 'getState' | 'info'>;

export async function run(core: Core, request: typeof fetch = fetch): Promise<void> {
  const url = brokerURL(core.getInput('broker-url', { required: true }));
  const jwt = await core.getIDToken(audience(url));
  core.setSecret(jwt);
  const credential = await exchange(url, jwt, request);
  core.setSecret(credential.token);
  // Persist for cleanup before exposing the token to subsequent steps.
  core.saveState('token', credential.token);
  core.setOutput('token', credential.token);
  core.setOutput('expires-at', credential.expires_at);
}

export async function cleanup(core: Core, request: typeof fetch = fetch): Promise<void> {
  const token = core.getState('token');
  if (!token) return;
  core.setSecret(token);
  await revoke(token, request);
  core.info('Broker token revoked (or already expired).');
}
