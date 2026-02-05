import { Hono } from 'hono';
import type { AppEnv } from '../types';

const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function validateSlug(raw: string): string | null {
  const slug = raw.trim().toLowerCase();
  if (!slug) return null;
  if (!SLUG_RE.test(slug)) return null;
  return slug;
}

function unauthorized(): Response {
  return new Response('Unauthorized', {
    status: 401,
    headers: { 'Content-Type': 'text/plain' },
  });
}

function requirePlatformAuth(c: { env: any; req: any }): Response | null {
  const expected = c.env.PLATFORM_ADMIN_TOKEN;
  if (!expected) {
    return new Response('Missing PLATFORM_ADMIN_TOKEN', { status: 500 });
  }
  const auth = c.req.header('authorization') || '';
  const prefix = 'Bearer ';
  if (!auth.startsWith(prefix)) return unauthorized();
  const token = auth.slice(prefix.length).trim();
  if (token !== expected) return unauthorized();
  return null;
}

const platformRoutes = new Hono<AppEnv>();

platformRoutes.get('/__platform/health', (c) => {
  return c.json({ ok: true });
});

platformRoutes.put('/__platform/tenants/:slug/config', async (c) => {
  const err = requirePlatformAuth(c);
  if (err) return err;

  const slug = validateSlug(c.req.param('slug') || '');
  if (!slug) return c.json({ error: 'Invalid slug' }, 400);
  if (!c.env.TENANT_CONFIG) return c.json({ error: 'Missing TENANT_CONFIG' }, 500);

  const body = await c.req.json().catch(() => null);
  if (!body || typeof body !== 'object') return c.json({ error: 'Invalid JSON body' }, 400);

  const id = c.env.TENANT_CONFIG.idFromName(slug);
  const stub = c.env.TENANT_CONFIG.get(id);
  const res = await stub.fetch('https://tenant-config/config', {
    method: 'PUT',
    body: JSON.stringify({ ...body, slug }),
    headers: { 'Content-Type': 'application/json' },
  });
  const text = await res.text();
  if (!res.ok) return new Response(text, { status: res.status });
  return new Response(text, { status: 200, headers: { 'Content-Type': 'application/json' } });
});

platformRoutes.delete('/__platform/tenants/:slug/config', async (c) => {
  const err = requirePlatformAuth(c);
  if (err) return err;
  const slug = validateSlug(c.req.param('slug') || '');
  if (!slug) return c.json({ error: 'Invalid slug' }, 400);
  if (!c.env.TENANT_CONFIG) return c.json({ error: 'Missing TENANT_CONFIG' }, 500);

  const id = c.env.TENANT_CONFIG.idFromName(slug);
  const stub = c.env.TENANT_CONFIG.get(id);
  const res = await stub.fetch('https://tenant-config/config', { method: 'DELETE' });
  const text = await res.text();
  if (!res.ok) return new Response(text, { status: res.status });
  return new Response(text, { status: 200, headers: { 'Content-Type': 'application/json' } });
});

platformRoutes.get('/__platform/tenants/:slug/config', async (c) => {
  const err = requirePlatformAuth(c);
  if (err) return err;
  const slug = validateSlug(c.req.param('slug') || '');
  if (!slug) return c.json({ error: 'Invalid slug' }, 400);
  if (!c.env.TENANT_CONFIG) return c.json({ error: 'Missing TENANT_CONFIG' }, 500);

  const id = c.env.TENANT_CONFIG.idFromName(slug);
  const stub = c.env.TENANT_CONFIG.get(id);
  return await stub.fetch('https://tenant-config/config', { method: 'GET' });
});

export { platformRoutes };
