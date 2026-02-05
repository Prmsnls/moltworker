export type TenantRuntimeConfig = {
  slug: string;
  gatewayToken: string;
  openrouterApiKey?: string;
  devMode?: boolean;
  debugRoutes?: boolean;
  updatedAtMs: number;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function parseBool(value: unknown, fallback: boolean): boolean {
  if (typeof value === 'boolean') return value;
  return fallback;
}

function parseString(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    throw new Error(`Invalid ${field} (expected string)`);
  }
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`Invalid ${field} (empty)`);
  return trimmed;
}

export class TenantConfigDO implements DurableObject {
  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/health') {
      return new Response('ok', { status: 200, headers: { 'Content-Type': 'text/plain' } });
    }

    if (url.pathname !== '/config') {
      return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain' } });
    }

    if (request.method === 'GET') {
      const cfg = (await this.state.storage.get('config')) as TenantRuntimeConfig | undefined;
      if (!cfg) return new Response('Not found', { status: 404 });
      return Response.json(cfg);
    }

    if (request.method === 'PUT' || request.method === 'POST') {
      const body = (await request.json().catch(() => null)) as unknown;
      if (!isRecord(body)) {
        return Response.json({ error: 'Invalid JSON body' }, { status: 400 });
      }

      const slug = parseString(body.slug, 'slug').toLowerCase();
      const gatewayToken = parseString(body.gatewayToken, 'gatewayToken');
      const openrouterApiKeyRaw = body.openrouterApiKey;
      const openrouterApiKey =
        typeof openrouterApiKeyRaw === 'string' && openrouterApiKeyRaw.trim()
          ? openrouterApiKeyRaw.trim()
          : undefined;

      const cfg: TenantRuntimeConfig = {
        slug,
        gatewayToken,
        openrouterApiKey,
        devMode: parseBool(body.devMode, false),
        debugRoutes: parseBool(body.debugRoutes, false),
        updatedAtMs: Date.now(),
      };
      await this.state.storage.put('config', cfg);
      return Response.json({ ok: true });
    }

    if (request.method === 'DELETE') {
      await this.state.storage.delete('config');
      return Response.json({ ok: true });
    }

    return new Response('Method not allowed', { status: 405 });
  }
}
