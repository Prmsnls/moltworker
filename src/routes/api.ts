import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { createAccessMiddleware } from '../auth';
import {
  ensureMoltbotGateway,
  findExistingMoltbotProcess,
  mountR2Storage,
  syncToR2,
  waitForProcess,
} from '../gateway';
import { R2_MOUNT_PATH } from '../config';

// CLI commands can take 10-15 seconds to complete due to WebSocket connection overhead
const CLI_TIMEOUT_MS = 20000;

/**
 * API routes
 * - /api/admin/* - Protected admin API routes
 *
 * Note: /api/status is handled by publicRoutes (no auth required)
 */
const api = new Hono<AppEnv>();

/**
 * Admin API routes - protected by Cloudflare Access or tenant token
 */
const adminApi = new Hono<AppEnv>();

adminApi.use('*', async (c, next) => {
  if (c.env.PLATFORM_MODE === 'true') {
    const cfg = c.get('tenantConfig');
    if (!cfg) return c.json({ error: 'Tenant not configured' }, 404);

    const url = new URL(c.req.url);
    const token = url.searchParams.get('token') || '';
    if (!token || token !== cfg.gatewayToken) {
      return c.json({ error: 'Unauthorized' }, 401);
    }
    return next();
  }
  return createAccessMiddleware({ type: 'json' })(c, next);
});

adminApi.get('/devices', async (c) => {
  const sandbox = c.get('sandbox');

  try {
    await ensureMoltbotGateway(sandbox, c.env, c.get('tenantConfig'));

    const proc = await sandbox.startProcess('clawdbot devices list --json --url ws://localhost:18789');
    await waitForProcess(proc, CLI_TIMEOUT_MS);

    const logs = await proc.getLogs();
    const stdout = logs.stdout || '';
    const stderr = logs.stderr || '';

    try {
      const jsonMatch = stdout.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const data = JSON.parse(jsonMatch[0]);
        return c.json(data);
      }
      return c.json({ pending: [], paired: [], raw: stdout, stderr });
    } catch {
      return c.json({ pending: [], paired: [], raw: stdout, stderr, parseError: 'Failed to parse CLI output' });
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: errorMessage }, 500);
  }
});

adminApi.post('/devices/:requestId/approve', async (c) => {
  const sandbox = c.get('sandbox');
  const requestId = c.req.param('requestId');

  if (!requestId) {
    return c.json({ error: 'requestId is required' }, 400);
  }

  try {
    await ensureMoltbotGateway(sandbox, c.env, c.get('tenantConfig'));

    const proc = await sandbox.startProcess(`clawdbot devices approve ${requestId} --url ws://localhost:18789`);
    await waitForProcess(proc, CLI_TIMEOUT_MS);

    const logs = await proc.getLogs();
    const stdout = logs.stdout || '';
    const stderr = logs.stderr || '';
    const success = stdout.toLowerCase().includes('approved') || proc.exitCode === 0;

    return c.json({
      success,
      requestId,
      message: success ? 'Device approved' : 'Approval may have failed',
      stdout,
      stderr,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: errorMessage }, 500);
  }
});

adminApi.post('/devices/approve-all', async (c) => {
  const sandbox = c.get('sandbox');

  try {
    await ensureMoltbotGateway(sandbox, c.env, c.get('tenantConfig'));

    const listProc = await sandbox.startProcess('clawdbot devices list --json --url ws://localhost:18789');
    await waitForProcess(listProc, CLI_TIMEOUT_MS);

    const listLogs = await listProc.getLogs();
    const stdout = listLogs.stdout || '';

    let pending: Array<{ requestId: string }> = [];
    try {
      const jsonMatch = stdout.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const data = JSON.parse(jsonMatch[0]);
        pending = data.pending || [];
      }
    } catch {
      return c.json({ error: 'Failed to parse device list', raw: stdout }, 500);
    }

    if (pending.length === 0) {
      return c.json({ approved: [], message: 'No pending devices to approve' });
    }

    const results: Array<{ requestId: string; success: boolean; error?: string }> = [];
    for (const device of pending) {
      try {
        const approveProc = await sandbox.startProcess(
          `clawdbot devices approve ${device.requestId} --url ws://localhost:18789`,
        );
        await waitForProcess(approveProc, CLI_TIMEOUT_MS);

        const approveLogs = await approveProc.getLogs();
        const success = approveLogs.stdout?.toLowerCase().includes('approved') || approveProc.exitCode === 0;
        results.push({ requestId: device.requestId, success });
      } catch (err) {
        results.push({
          requestId: device.requestId,
          success: false,
          error: err instanceof Error ? err.message : 'Unknown error',
        });
      }
    }

    const approvedCount = results.filter((r) => r.success).length;
    return c.json({
      approved: results.filter((r) => r.success).map((r) => r.requestId),
      failed: results.filter((r) => !r.success),
      message: `Approved ${approvedCount} of ${pending.length} device(s)`,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: errorMessage }, 500);
  }
});

adminApi.get('/storage', async (c) => {
  const sandbox = c.get('sandbox');
  const hasCredentials = !!(c.env.R2_ACCESS_KEY_ID && c.env.R2_SECRET_ACCESS_KEY && c.env.CF_ACCOUNT_ID);

  const missing: string[] = [];
  if (!c.env.R2_ACCESS_KEY_ID) missing.push('R2_ACCESS_KEY_ID');
  if (!c.env.R2_SECRET_ACCESS_KEY) missing.push('R2_SECRET_ACCESS_KEY');
  if (!c.env.CF_ACCOUNT_ID) missing.push('CF_ACCOUNT_ID');

  let lastSync: string | null = null;
  if (hasCredentials) {
    try {
      const slug = c.get('tenantSlug') || 'default';
      if (c.env.PLATFORM_MODE === 'true' && slug === 'default') {
        return c.json({ configured: false, message: 'Tenant missing from request' }, 400);
      }
      await mountR2Storage(sandbox, c.env, slug);
      const proc = await sandbox.startProcess(
        `cat ${R2_MOUNT_PATH}/tenants/${slug}/.last-sync 2>/dev/null || echo ""`,
      );
      await waitForProcess(proc, 5000);
      const logs = await proc.getLogs();
      const timestamp = logs.stdout?.trim();
      if (timestamp) lastSync = timestamp;
    } catch {
      // ignore
    }
  }

  return c.json({
    configured: hasCredentials,
    missing: missing.length > 0 ? missing : undefined,
    lastSync,
    message: hasCredentials
      ? 'R2 storage is configured. Your data will persist across container restarts.'
      : 'R2 storage is not configured. Paired devices and conversations will be lost when the container restarts.',
  });
});

adminApi.post('/storage/sync', async (c) => {
  const sandbox = c.get('sandbox');
  const slug = c.get('tenantSlug') || 'default';
  if (c.env.PLATFORM_MODE === 'true' && slug === 'default') {
    return c.json({ error: 'Tenant missing from request' }, 400);
  }

  const result = await syncToR2(sandbox, c.env, slug);
  if (result.success) {
    return c.json({ success: true, message: 'Sync completed successfully', lastSync: result.lastSync });
  }
  const status = result.error?.includes('not configured') ? 400 : 500;
  return c.json({ success: false, error: result.error, details: result.details }, status);
});

adminApi.post('/gateway/restart', async (c) => {
  const sandbox = c.get('sandbox');

  try {
    const existingProcess = await findExistingMoltbotProcess(sandbox);
    if (existingProcess) {
      console.log('Killing existing gateway process:', existingProcess.id);
      try {
        await existingProcess.kill();
      } catch (killErr) {
        console.error('Error killing process:', killErr);
      }
      await new Promise((r) => setTimeout(r, 2000));
    }

    const bootPromise = ensureMoltbotGateway(sandbox, c.env, c.get('tenantConfig')).catch((err) => {
      console.error('Gateway restart failed:', err);
    });
    c.executionCtx.waitUntil(bootPromise);

    return c.json({
      success: true,
      message: existingProcess
        ? 'Gateway process killed, new instance starting...'
        : 'No existing process found, starting new instance...',
      previousProcessId: existingProcess?.id,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: errorMessage }, 500);
  }
});

api.route('/admin', adminApi);

export { api };
