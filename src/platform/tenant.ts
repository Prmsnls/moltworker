import type { MoltbotEnv } from '../types';
import type { TenantRuntimeConfig } from './tenantConfig';

const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function validateSlug(raw: string): string | null {
  const slug = raw.trim().toLowerCase();
  if (!slug) return null;
  if (!SLUG_RE.test(slug)) return null;
  return slug;
}

export function resolveTenantSlug(request: Request, env: MoltbotEnv): string | null {
  const url = new URL(request.url);
  const fromHeader = request.headers.get('x-tenant-slug');
  if (fromHeader) {
    const slug = validateSlug(fromHeader);
    if (slug) return slug;
  }

  const publicDomain = (env.PUBLIC_DOMAIN || 'workers.openputer.com').trim();
  const hostname = url.hostname;
  if (hostname === publicDomain) return null;
  if (hostname.endsWith(`.${publicDomain}`)) {
    const sub = hostname.slice(0, hostname.length - publicDomain.length - 1);
    return validateSlug(sub);
  }

  // Support workers.dev / direct calls.
  const fromQuery = url.searchParams.get('tenant');
  if (fromQuery) return validateSlug(fromQuery);

  return null;
}

export async function getTenantConfig(
  env: MoltbotEnv,
  slug: string,
): Promise<TenantRuntimeConfig | null> {
  if (!env.TENANT_CONFIG) {
    throw new Error('Missing TENANT_CONFIG binding');
  }

  const id = env.TENANT_CONFIG.idFromName(slug);
  const stub = env.TENANT_CONFIG.get(id);
  const res = await stub.fetch('https://tenant-config/config', { method: 'GET' });
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new Error(`Failed to load tenant config (${res.status})`);
  }
  return (await res.json()) as TenantRuntimeConfig;
}
