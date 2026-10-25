export type Credential = { token: string; expires_at: string };

export function brokerURL(raw: string): URL {
  const url = new URL(raw);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    throw new Error('broker-url must be HTTPS without credentials, query or fragment');
  }
  // One canonical base URL is used both for the audience and the request.
  url.pathname = url.pathname.replace(/\/+$/, '');
  return url;
}

export function audience(url: URL): string {
  return url.href.replace(/\/$/, '');
}

export async function exchange(url: URL, jwt: string, request: typeof fetch = fetch): Promise<Credential> {
  const response = await request(`${audience(url)}/v1/token`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${jwt}`, Accept: 'application/json' },
    redirect: 'error',
    signal: AbortSignal.timeout(30_000),
  });
  // Never print response bodies or raw network errors: they can contain credentials.
  if (!response.ok) throw new Error(`Broker returned HTTP ${response.status}`);
  const data: unknown = await response.json();
  if (!data || typeof data !== 'object' || !('token' in data) || !('expires_at' in data) ||
      typeof data.token !== 'string' || !/^[A-Za-z0-9_]+$/.test(data.token) ||
      typeof data.expires_at !== 'string' || !(Date.parse(data.expires_at) > Date.now())) {
    throw new Error('Invalid broker response');
  }
  return { token: data.token, expires_at: data.expires_at };
}

export async function revoke(token: string, request: typeof fetch = fetch): Promise<void> {
  const response = await request('https://api.github.com/installation/token', {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'smpio/gha-token-broker',
    },
    redirect: 'error',
    signal: AbortSignal.timeout(15_000),
  });
  // Revocation is idempotent when the token has expired or was already revoked.
  if (response.status !== 204 && response.status !== 401) {
    throw new Error(`GitHub revocation returned HTTP ${response.status}`);
  }
}
