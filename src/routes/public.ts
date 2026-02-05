import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { MOLTBOT_PORT } from '../config';
import { ensureMoltbotGateway, findExistingMoltbotProcess } from '../gateway';

async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  label: string,
): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error(`${label} timed out after ${ms}ms`));
    }, ms);
  });

  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

/**
 * Public routes - NO Cloudflare Access authentication required
 *
 * These routes are mounted BEFORE the auth middleware is applied.
 * Includes: health checks, static assets, and public API endpoints.
 */
const publicRoutes = new Hono<AppEnv>();

let lastStartAttemptAtMs = 0;
let lastStartError: string | null = null;
const START_THROTTLE_MS = 15_000;

function safeErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

// GET /sandbox-health - Health check endpoint
publicRoutes.get('/sandbox-health', (c) => {
  return c.json({
    status: 'ok',
    service: 'moltbot-sandbox',
    gateway_port: MOLTBOT_PORT,
  });
});

// GET /logo.png - Serve logo from ASSETS binding
publicRoutes.get('/logo.png', (c) => {
  return c.env.ASSETS.fetch(c.req.raw);
});

// GET /logo-small.png - Serve small logo from ASSETS binding
publicRoutes.get('/logo-small.png', (c) => {
  return c.env.ASSETS.fetch(c.req.raw);
});

// GET /api/status - Public health check for gateway status (no auth required)
publicRoutes.get('/api/status', async (c) => {
  const sandbox = c.get('sandbox');
  const cfg = c.get('tenantConfig');
  if (c.env.PLATFORM_MODE === 'true' && !cfg) {
    return c.json({ ok: false, status: 'unconfigured' }, 404);
  }

  try {
    const process = await findExistingMoltbotProcess(sandbox);
    if (!process) {
      // Kick off startup in the background so the loading screen can converge.
      const now = Date.now();
      if (now - lastStartAttemptAtMs > START_THROTTLE_MS) {
        lastStartAttemptAtMs = now;
        lastStartError = null;
        c.executionCtx.waitUntil(
          ensureMoltbotGateway(sandbox, c.env, cfg)
            .then(() => {
              lastStartError = null;
            })
            .catch((e: unknown) => {
              lastStartError = safeErrorMessage(e);
              console.error('[STATUS] Background start failed:', lastStartError);
            }),
        );
      }
      return c.json({
        ok: false,
        status: 'starting',
        lastStartError,
      });
    }

    // Process exists, check if it's actually responding
    // Try to reach the gateway with a short timeout
    try {
      await withTimeout(
        process.waitForPort(MOLTBOT_PORT, { mode: 'tcp', timeout: 5000 }),
        5500,
        'process.waitForPort',
      );
      return c.json({ ok: true, status: 'running', processId: process.id });
    } catch {
      return c.json({ ok: false, status: 'not_responding', processId: process.id });
    }
  } catch (err) {
    const msg = safeErrorMessage(err);
    return c.json({ ok: false, status: 'error', error: msg, lastStartError });
  }
});

// GET /_admin/assets/* - Admin UI static assets (CSS, JS need to load for login redirect)
// Assets are built to dist/client with base "/_admin/"
publicRoutes.get('/_admin/assets/*', async (c) => {
  const url = new URL(c.req.url);
  // Rewrite /_admin/assets/* to /assets/* for the ASSETS binding
  const assetPath = url.pathname.replace('/_admin/assets/', '/assets/');
  const assetUrl = new URL(assetPath, url.origin);
  return c.env.ASSETS.fetch(new Request(assetUrl.toString(), c.req.raw));
});

export { publicRoutes };
