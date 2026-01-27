/**
 * Clawdbot + Cloudflare Sandbox
 *
 * This Worker runs Clawdbot personal AI assistant in a Cloudflare Sandbox container.
 * It proxies all requests to the Clawdbot Gateway's web UI and WebSocket endpoint.
 *
 * Features:
 * - Web UI (Control Dashboard + WebChat) at /
 * - WebSocket support for real-time communication
 * - Configuration via environment secrets
 *
 * Required secrets (set via `wrangler secret put`):
 * - ANTHROPIC_API_KEY: Your Anthropic API key
 *
 * Optional secrets:
 * - CLAWDBOT_GATEWAY_TOKEN: Token to protect gateway access
 * - TELEGRAM_BOT_TOKEN: Telegram bot token
 * - DISCORD_BOT_TOKEN: Discord bot token
 * - SLACK_BOT_TOKEN + SLACK_APP_TOKEN: Slack tokens
 */

import { Hono } from 'hono';
import { getSandbox, Sandbox } from '@cloudflare/sandbox';
import type { Process } from '@cloudflare/sandbox';

export { Sandbox };

const CLAWDBOT_PORT = 18789;
const STARTUP_TIMEOUT_MS = 180_000; // 3 minutes for clawdbot to start

// Types
interface ClawdbotEnv {
  Sandbox: DurableObjectNamespace<Sandbox>;
  ASSETS: Fetcher; // Assets binding for admin UI static files
  CLAWDBOT_BUCKET: R2Bucket; // R2 bucket for persistent storage
  ANTHROPIC_API_KEY?: string;
  OPENAI_API_KEY?: string;
  CLAWDBOT_GATEWAY_TOKEN?: string;
  CLAWDBOT_DEV_MODE?: string;
  CLAWDBOT_BIND_MODE?: string;
  LOCAL_DEV?: string; // Set to 'true' to skip CF Access auth (for local development)
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_DM_POLICY?: string;
  DISCORD_BOT_TOKEN?: string;
  DISCORD_DM_POLICY?: string;
  SLACK_BOT_TOKEN?: string;
  SLACK_APP_TOKEN?: string;
  // Cloudflare Access configuration for admin routes
  CF_ACCESS_TEAM_DOMAIN?: string; // e.g., 'myteam.cloudflareaccess.com'
  CF_ACCESS_AUD?: string; // Application Audience (AUD) tag
  // R2 credentials for bucket mounting (set via wrangler secret)
  AWS_ACCESS_KEY_ID?: string;
  AWS_SECRET_ACCESS_KEY?: string;
  CF_ACCOUNT_ID?: string; // Cloudflare account ID for R2 endpoint
}

interface AccessUser {
  email: string;
  name?: string;
}

type AppEnv = {
  Bindings: ClawdbotEnv;
  Variables: {
    sandbox: Sandbox;
    accessUser?: AccessUser;
  };
};

// Helper functions
function buildEnvVars(env: ClawdbotEnv, r2Mounted: boolean): Record<string, string> {
  const envVars: Record<string, string> = {};

  if (env.ANTHROPIC_API_KEY) envVars.ANTHROPIC_API_KEY = env.ANTHROPIC_API_KEY;
  if (env.OPENAI_API_KEY) envVars.OPENAI_API_KEY = env.OPENAI_API_KEY;
  if (env.CLAWDBOT_GATEWAY_TOKEN) envVars.CLAWDBOT_GATEWAY_TOKEN = env.CLAWDBOT_GATEWAY_TOKEN;
  if (env.CLAWDBOT_DEV_MODE) envVars.CLAWDBOT_DEV_MODE = env.CLAWDBOT_DEV_MODE;
  if (env.CLAWDBOT_BIND_MODE) envVars.CLAWDBOT_BIND_MODE = env.CLAWDBOT_BIND_MODE;
  if (env.TELEGRAM_BOT_TOKEN) envVars.TELEGRAM_BOT_TOKEN = env.TELEGRAM_BOT_TOKEN;
  if (env.TELEGRAM_DM_POLICY) envVars.TELEGRAM_DM_POLICY = env.TELEGRAM_DM_POLICY;
  if (env.DISCORD_BOT_TOKEN) envVars.DISCORD_BOT_TOKEN = env.DISCORD_BOT_TOKEN;
  if (env.DISCORD_DM_POLICY) envVars.DISCORD_DM_POLICY = env.DISCORD_DM_POLICY;
  if (env.SLACK_BOT_TOKEN) envVars.SLACK_BOT_TOKEN = env.SLACK_BOT_TOKEN;
  if (env.SLACK_APP_TOKEN) envVars.SLACK_APP_TOKEN = env.SLACK_APP_TOKEN;

  // If R2 is mounted, tell clawdbot to use it for state/config
  if (r2Mounted) {
    envVars.CLAWDBOT_STATE_DIR = R2_MOUNT_PATH;
    envVars.CLAWDBOT_CONFIG_PATH = `${R2_MOUNT_PATH}/clawdbot.json`;
  }

  return envVars;
}

async function findExistingClawdbotProcess(sandbox: Sandbox): Promise<Process | null> {
  try {
    const processes = await sandbox.listProcesses();
    for (const proc of processes) {
      // Only match the gateway process, not CLI commands like "clawdbot devices list"
      const isGatewayProcess = 
        proc.command.includes('start-clawdbot.sh') ||
        proc.command.includes('clawdbot gateway');
      const isCliCommand = 
        proc.command.includes('clawdbot devices') ||
        proc.command.includes('clawdbot --version');
      
      if (isGatewayProcess && !isCliCommand) {
        if (proc.status === 'starting' || proc.status === 'running') {
          return proc;
        }
      }
    }
  } catch (e) {
    console.log('Could not list processes:', e);
  }
  return null;
}

// Mount R2 bucket for persistent storage
// Mount at /data/clawdbot and use CLAWDBOT_STATE_DIR env var to point clawdbot there
const R2_MOUNT_PATH = '/data/clawdbot';

async function mountR2Storage(sandbox: Sandbox, env: ClawdbotEnv): Promise<boolean> {
  // Skip if R2 credentials are not configured
  if (!env.AWS_ACCESS_KEY_ID || !env.AWS_SECRET_ACCESS_KEY || !env.CF_ACCOUNT_ID) {
    console.log('R2 storage not configured (missing AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, or CF_ACCOUNT_ID)');
    return false;
  }

  try {
    console.log('Mounting R2 bucket at', R2_MOUNT_PATH);
    await sandbox.mountBucket('clawdbot-data', R2_MOUNT_PATH, {
      endpoint: `https://${env.CF_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    });
    console.log('R2 bucket mounted successfully - clawdbot data will persist across sessions');
    return true;
  } catch (err) {
    // Don't fail if mounting fails - clawdbot can still run without persistent storage
    console.error('Failed to mount R2 bucket:', err);
    return false;
  }
}

// Internal implementation - actually starts the gateway
async function doEnsureClawdbotGateway(sandbox: Sandbox, env: ClawdbotEnv): Promise<Process> {
  // Mount R2 storage for persistent data (non-blocking if not configured)
  const r2Mounted = await mountR2Storage(sandbox, env);

  // Check if Clawdbot is already running or starting
  const existingProcess = await findExistingClawdbotProcess(sandbox);
  if (existingProcess) {
    console.log('Found existing Clawdbot process:', existingProcess.id, 'status:', existingProcess.status);

    // Always use full startup timeout - a process can be "running" but not ready yet
    // (e.g., just started by another concurrent request). Using a shorter timeout
    // causes race conditions where we kill processes that are still initializing.
    try {
      console.log('Waiting for Clawdbot gateway on port', CLAWDBOT_PORT, 'timeout:', STARTUP_TIMEOUT_MS);
      await existingProcess.waitForPort(CLAWDBOT_PORT, { mode: 'tcp', timeout: STARTUP_TIMEOUT_MS });
      console.log('Clawdbot gateway is reachable');
      return existingProcess;
    } catch (e) {
      // Timeout waiting for port - process is likely dead or stuck, kill and restart
      console.log('Existing process not reachable after full timeout, killing and restarting...');
      try {
        await existingProcess.kill();
      } catch (killError) {
        console.log('Failed to kill process:', killError);
      }
    }
  }

  // Start a new Clawdbot gateway
  console.log('Starting new Clawdbot gateway...');
  const envVars = buildEnvVars(env, r2Mounted);
  const command = '/usr/local/bin/start-clawdbot.sh';

  console.log('Starting process with command:', command);
  console.log('Environment vars being passed:', Object.keys(envVars));

  let process: Process;
  try {
    process = await sandbox.startProcess(command, {
      env: Object.keys(envVars).length > 0 ? envVars : undefined,
    });
    console.log('Process started with id:', process.id, 'status:', process.status);
  } catch (startErr) {
    console.error('Failed to start process:', startErr);
    throw startErr;
  }

  // Wait for the gateway to be ready
  try {
    console.log('Waiting for Clawdbot gateway to be ready on port', CLAWDBOT_PORT);
    await process.waitForPort(CLAWDBOT_PORT, { mode: 'tcp', timeout: STARTUP_TIMEOUT_MS });
    console.log('Clawdbot gateway is ready!');

    const logs = await process.getLogs();
    if (logs.stdout) console.log('Clawdbot stdout:', logs.stdout);
    if (logs.stderr) console.log('Clawdbot stderr:', logs.stderr);
  } catch (e) {
    console.error('waitForPort failed:', e);
    try {
      const logs = await process.getLogs();
      console.error('Clawdbot startup failed. Stderr:', logs.stderr);
      console.error('Clawdbot startup failed. Stdout:', logs.stdout);
      throw new Error(`Clawdbot gateway failed to start. Stderr: ${logs.stderr || '(empty)'}`);
    } catch (logErr) {
      console.error('Failed to get logs:', logErr);
      throw e;
    }
  }

  return process;
}

// Alias for the internal function - no lock needed since doEnsureClawdbotGateway
// already checks for existing processes and handles the startup logic
async function ensureClawdbotGateway(sandbox: Sandbox, env: ClawdbotEnv): Promise<Process> {
  return doEnsureClawdbotGateway(sandbox, env);
}

// Cloudflare Access JWT verification
// Based on: https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/

interface JWTPayload {
  aud: string[];
  email: string;
  exp: number;
  iat: number;
  iss: string;
  name?: string;
  sub: string;
  type: string;
}

interface JWK extends JsonWebKey {
  kid?: string;
}

interface JWKS {
  keys: JWK[];
}

// Cache for JWKS to avoid fetching on every request
let jwksCache: { keys: Map<string, CryptoKey>; fetchedAt: number } | null = null;
const JWKS_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

async function getJWKS(teamDomain: string): Promise<Map<string, CryptoKey>> {
  const now = Date.now();
  if (jwksCache && now - jwksCache.fetchedAt < JWKS_CACHE_TTL_MS) {
    return jwksCache.keys;
  }

  const certsUrl = `https://${teamDomain}/cdn-cgi/access/certs`;
  const response = await fetch(certsUrl);
  if (!response.ok) {
    throw new Error(`Failed to fetch JWKS from ${certsUrl}: ${response.status}`);
  }

  const jwks: JWKS = await response.json();
  const keys = new Map<string, CryptoKey>();

  for (const jwk of jwks.keys) {
    if (jwk.kid && jwk.kty === 'RSA') {
      const key = await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify']
      );
      keys.set(jwk.kid, key);
    }
  }

  jwksCache = { keys, fetchedAt: now };
  return keys;
}

function base64UrlDecode(str: string): Uint8Array {
  // Replace URL-safe chars and add padding
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(base64 + padding);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function verifyAccessJWT(
  token: string,
  teamDomain: string,
  expectedAud: string
): Promise<JWTPayload> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  // Decode header to get kid
  const headerJson = new TextDecoder().decode(base64UrlDecode(headerB64));
  const header = JSON.parse(headerJson);
  const kid = header.kid;

  if (!kid) {
    throw new Error('JWT header missing kid');
  }

  // Get signing keys
  const keys = await getJWKS(teamDomain);
  const key = keys.get(kid);

  if (!key) {
    throw new Error(`Unknown signing key: ${kid}`);
  }

  // Verify signature
  const signatureData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signatureBytes = base64UrlDecode(signatureB64);
  // Get the underlying ArrayBuffer for the signature
  const signature = signatureBytes.buffer.slice(
    signatureBytes.byteOffset,
    signatureBytes.byteOffset + signatureBytes.byteLength
  ) as ArrayBuffer;

  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    signature,
    signatureData
  );

  if (!valid) {
    throw new Error('Invalid JWT signature');
  }

  // Decode and validate payload
  const payloadJson = new TextDecoder().decode(base64UrlDecode(payloadB64));
  const payload: JWTPayload = JSON.parse(payloadJson);

  // Verify expiration
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) {
    throw new Error('JWT has expired');
  }

  // Verify audience
  if (!payload.aud.includes(expectedAud)) {
    throw new Error('JWT audience mismatch');
  }

  // Verify issuer
  const expectedIss = `https://${teamDomain}`;
  if (payload.iss !== expectedIss) {
    throw new Error('JWT issuer mismatch');
  }

  return payload;
}

// Helper: Check if running locally (skip CF Access auth)
function isLocalDev(env: ClawdbotEnv): boolean {
  return env.LOCAL_DEV === 'true';
}

// API routes sub-router (protected by Cloudflare Access)
const api = new Hono<AppEnv>();

// Middleware: Verify Cloudflare Access JWT for all API routes (skip in dev mode)
api.use('*', async (c, next) => {
  // Skip auth in local dev mode
  if (isLocalDev(c.env)) {
    c.set('accessUser', { email: 'dev@localhost', name: 'Dev User' });
    return next();
  }

  const teamDomain = c.env.CF_ACCESS_TEAM_DOMAIN;
  const expectedAud = c.env.CF_ACCESS_AUD;

  if (!teamDomain || !expectedAud) {
    return c.json({
      error: 'Cloudflare Access not configured',
      hint: 'Set CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD environment variables',
    }, 500);
  }

  // Get JWT from header or cookie
  const jwtHeader = c.req.header('CF-Access-JWT-Assertion');
  const jwtCookie = c.req.raw.headers.get('Cookie')
    ?.split(';')
    .find(cookie => cookie.trim().startsWith('CF_Authorization='))
    ?.split('=')[1];

  const jwt = jwtHeader || jwtCookie;

  if (!jwt) {
    return c.json({
      error: 'Unauthorized',
      hint: 'Missing Cloudflare Access JWT. Ensure this route is protected by Cloudflare Access.',
    }, 401);
  }

  try {
    const payload = await verifyAccessJWT(jwt, teamDomain, expectedAud);
    c.set('accessUser', { email: payload.email, name: payload.name });
    await next();
  } catch (err) {
    console.error('Access JWT verification failed:', err);
    return c.json({
      error: 'Unauthorized',
      details: err instanceof Error ? err.message : 'JWT verification failed',
    }, 401);
  }
});

// GET /api/devices - List pending and paired devices
api.get('/devices', async (c) => {
  const sandbox = c.get('sandbox');

  try {
    // Ensure clawdbot is running first
    await ensureClawdbotGateway(sandbox, c.env);

    // Run clawdbot CLI to list devices
    const proc = await sandbox.startProcess('clawdbot devices list --json');

    // Wait for command to complete
    let attempts = 0;
    while (attempts < 10) {
      await new Promise(r => setTimeout(r, 500));
      if (proc.status !== 'running') break;
      attempts++;
    }

    const logs = await proc.getLogs();
    const stdout = logs.stdout || '';
    const stderr = logs.stderr || '';

    // Try to parse JSON output
    try {
      // Find JSON in output (may have other log lines)
      const jsonMatch = stdout.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const data = JSON.parse(jsonMatch[0]);
        return c.json(data);
      }

      // If no JSON found, return raw output
      return c.json({
        pending: [],
        paired: [],
        raw: stdout,
        stderr,
      });
    } catch {
      return c.json({
        pending: [],
        paired: [],
        raw: stdout,
        stderr,
        parseError: 'Failed to parse CLI output',
      });
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: errorMessage }, 500);
  }
});

// POST /api/devices/:requestId/approve - Approve a pending device
api.post('/devices/:requestId/approve', async (c) => {
  const sandbox = c.get('sandbox');
  const requestId = c.req.param('requestId');

  if (!requestId) {
    return c.json({ error: 'requestId is required' }, 400);
  }

  try {
    // Ensure clawdbot is running first
    await ensureClawdbotGateway(sandbox, c.env);

    // Run clawdbot CLI to approve the device
    const proc = await sandbox.startProcess(`clawdbot devices approve ${requestId}`);

    // Wait for command to complete
    let attempts = 0;
    while (attempts < 10) {
      await new Promise(r => setTimeout(r, 500));
      if (proc.status !== 'running') break;
      attempts++;
    }

    const logs = await proc.getLogs();
    const stdout = logs.stdout || '';
    const stderr = logs.stderr || '';

    // Check for success indicators
    const success = stdout.includes('approved') || proc.exitCode === 0;

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

// POST /api/devices/approve-all - Approve all pending devices
api.post('/devices/approve-all', async (c) => {
  const sandbox = c.get('sandbox');

  try {
    // Ensure clawdbot is running first
    await ensureClawdbotGateway(sandbox, c.env);

    // First, get the list of pending devices
    const listProc = await sandbox.startProcess('clawdbot devices list --json');

    let attempts = 0;
    while (attempts < 10) {
      await new Promise(r => setTimeout(r, 500));
      if (listProc.status !== 'running') break;
      attempts++;
    }

    const listLogs = await listProc.getLogs();
    const stdout = listLogs.stdout || '';

    // Parse pending devices
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

    // Approve each pending device
    const results: Array<{ requestId: string; success: boolean; error?: string }> = [];

    for (const device of pending) {
      try {
        const approveProc = await sandbox.startProcess(`clawdbot devices approve ${device.requestId}`);

        let approveAttempts = 0;
        while (approveAttempts < 10) {
          await new Promise(r => setTimeout(r, 500));
          if (approveProc.status !== 'running') break;
          approveAttempts++;
        }

        const approveLogs = await approveProc.getLogs();
        const success = approveLogs.stdout?.includes('approved') || approveProc.exitCode === 0;

        results.push({ requestId: device.requestId, success });
      } catch (err) {
        results.push({
          requestId: device.requestId,
          success: false,
          error: err instanceof Error ? err.message : 'Unknown error',
        });
      }
    }

    const approvedCount = results.filter(r => r.success).length;
    return c.json({
      approved: results.filter(r => r.success).map(r => r.requestId),
      failed: results.filter(r => !r.success),
      message: `Approved ${approvedCount} of ${pending.length} device(s)`,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: errorMessage }, 500);
  }
});

// POST /api/gateway/restart - Kill the current gateway and start a new one
api.post('/gateway/restart', async (c) => {
  const sandbox = c.get('sandbox');

  try {
    // Find and kill the existing gateway process
    const existingProcess = await findExistingClawdbotProcess(sandbox);
    
    if (existingProcess) {
      console.log('Killing existing gateway process:', existingProcess.id);
      try {
        await existingProcess.kill();
      } catch (killErr) {
        console.error('Error killing process:', killErr);
      }
      // Wait a moment for the process to die
      await new Promise(r => setTimeout(r, 2000));
    }

    // Start a new gateway in the background
    const bootPromise = ensureClawdbotGateway(sandbox, c.env).catch((err) => {
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

// Debug routes sub-router
const debug = new Hono<AppEnv>();

// GET /debug/version - Returns build info from inside the container
debug.get('/version', async (c) => {
  const sandbox = c.get('sandbox');
  try {
    // Read the build info file
    const buildProcess = await sandbox.startProcess('cat /root/.clawdbot/build-info.json');
    await new Promise(resolve => setTimeout(resolve, 500));
    const buildLogs = await buildProcess.getLogs();

    let buildInfo = null;
    try {
      buildInfo = JSON.parse(buildLogs.stdout || '{}');
    } catch {
      // File might not exist in older deployments
    }

    // Also get clawdbot version
    const versionProcess = await sandbox.startProcess('clawdbot --version');
    await new Promise(resolve => setTimeout(resolve, 500));
    const versionLogs = await versionProcess.getLogs();
    const clawdbotVersion = (versionLogs.stdout || versionLogs.stderr || '').trim();

    return c.json({
      container: buildInfo || { error: 'build-info.json not found (older deployment?)' },
      clawdbot_version: clawdbotVersion,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ status: 'error', message: `Failed to get version info: ${errorMessage}` }, 500);
  }
});

// GET /debug/processes - List all processes with optional logs
debug.get('/processes', async (c) => {
  const sandbox = c.get('sandbox');
  try {
    const processes = await sandbox.listProcesses();
    const includeLogs = c.req.query('logs') === 'true';

    const processData = await Promise.all(processes.map(async p => {
      const data: Record<string, unknown> = {
        id: p.id,
        command: p.command,
        status: p.status,
        startTime: p.startTime?.toISOString(),
        endTime: p.endTime?.toISOString(),
        exitCode: p.exitCode,
      };

      if (includeLogs) {
        try {
          const logs = await p.getLogs();
          data.stdout = logs.stdout || '';
          data.stderr = logs.stderr || '';
        } catch {
          data.logs_error = 'Failed to retrieve logs';
        }
      }

      return data;
    }));

    // Sort by status (running first, then starting, completed, failed)
    // Within each status, sort by startTime descending (newest first)
    const statusOrder: Record<string, number> = {
      'running': 0,
      'starting': 1,
      'completed': 2,
      'failed': 3,
    };
    
    processData.sort((a, b) => {
      const statusA = statusOrder[a.status as string] ?? 99;
      const statusB = statusOrder[b.status as string] ?? 99;
      if (statusA !== statusB) {
        return statusA - statusB;
      }
      // Within same status, sort by startTime descending
      const timeA = a.startTime as string || '';
      const timeB = b.startTime as string || '';
      return timeB.localeCompare(timeA);
    });

    return c.json({ count: processes.length, processes: processData });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: errorMessage }, 500);
  }
});

// GET /debug/logs - Returns container logs for debugging
debug.get('/logs', async (c) => {
  const sandbox = c.get('sandbox');
  try {
    const processId = c.req.query('id');
    let process: Process | null | undefined;

    if (processId) {
      const processes = await sandbox.listProcesses();
      process = processes.find(p => p.id === processId);
      if (!process) {
        return c.json({
          status: 'not_found',
          message: `Process ${processId} not found`,
          stdout: '',
          stderr: '',
        }, 404);
      }
    } else {
      process = await findExistingClawdbotProcess(sandbox);
      if (!process) {
        return c.json({
          status: 'no_process',
          message: 'No Clawdbot process is currently running',
          stdout: '',
          stderr: '',
        });
      }
    }

    const logs = await process.getLogs();
    return c.json({
      status: 'ok',
      process_id: process.id,
      process_status: process.status,
      stdout: logs.stdout || '',
      stderr: logs.stderr || '',
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return c.json({
      status: 'error',
      message: `Failed to get logs: ${errorMessage}`,
      stdout: '',
      stderr: '',
    }, 500);
  }
});

// Main app
const app = new Hono<AppEnv>();

// Middleware: Initialize sandbox for all requests
app.use('*', async (c, next) => {
  const sandbox = getSandbox(c.env.Sandbox, 'clawdbot');
  c.set('sandbox', sandbox);
  await next();
});

// Health check endpoint (before starting clawdbot)
app.get('/sandbox-health', (c) => {
  return c.json({
    status: 'ok',
    service: 'clawdbot-sandbox',
    gateway_port: CLAWDBOT_PORT,
  });
});



// Mount API routes (protected by Cloudflare Access)
app.route('/api', api);

// Admin UI routes (protected by Cloudflare Access)
// The static files will be served from /_admin/ and use the /api endpoints
const admin = new Hono<AppEnv>();

// Middleware: Verify Cloudflare Access JWT for admin UI (skip in local dev mode)
admin.use('*', async (c, next) => {
  // Skip auth in local dev mode
  if (isLocalDev(c.env)) {
    c.set('accessUser', { email: 'dev@localhost', name: 'Dev User' });
    return next();
  }

  const teamDomain = c.env.CF_ACCESS_TEAM_DOMAIN;
  const expectedAud = c.env.CF_ACCESS_AUD;

  if (!teamDomain || !expectedAud) {
    return c.html(`
      <html>
        <body>
          <h1>Admin UI Not Configured</h1>
          <p>Set CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD environment variables.</p>
        </body>
      </html>
    `, 500);
  }

  // Get JWT from header or cookie
  const jwtHeader = c.req.header('CF-Access-JWT-Assertion');
  const jwtCookie = c.req.raw.headers.get('Cookie')
    ?.split(';')
    .find(cookie => cookie.trim().startsWith('CF_Authorization='))
    ?.split('=')[1];

  const jwt = jwtHeader || jwtCookie;

  if (!jwt) {
    // Redirect to Access login if no JWT
    return c.redirect(`https://${teamDomain}`, 302);
  }

  try {
    const payload = await verifyAccessJWT(jwt, teamDomain, expectedAud);
    c.set('accessUser', { email: payload.email, name: payload.name });
    await next();
  } catch (err) {
    console.error('Access JWT verification failed:', err);
    return c.html(`
      <html>
        <body>
          <h1>Unauthorized</h1>
          <p>Your Cloudflare Access session is invalid or expired.</p>
          <a href="https://${teamDomain}">Login again</a>
        </body>
      </html>
    `, 401);
  }
});

// Serve admin UI static files via ASSETS binding
// Assets are built to dist/client with base "/_admin/"
// The built assets are at /assets/* in the dist folder, so we need to rewrite the path
admin.get('/assets/*', async (c) => {
  const url = new URL(c.req.url);
  // Rewrite /_admin/assets/* to /assets/* for the ASSETS binding
  const assetPath = url.pathname.replace('/_admin/assets/', '/assets/');
  const assetUrl = new URL(assetPath, url.origin);
  return c.env.ASSETS.fetch(new Request(assetUrl.toString(), c.req.raw));
});

// Serve index.html for all other admin routes (SPA)
admin.get('*', async (c) => {
  const url = new URL(c.req.url);
  return c.env.ASSETS.fetch(new Request(new URL('/index.html', url.origin).toString()));
});

app.route('/_admin', admin);

// Mount debug routes (protected by Cloudflare Access, skip in local dev mode)
app.use('/debug/*', async (c, next) => {
  // Skip auth in local dev mode
  if (isLocalDev(c.env)) {
    c.set('accessUser', { email: 'dev@localhost', name: 'Dev User' });
    return next();
  }

  const teamDomain = c.env.CF_ACCESS_TEAM_DOMAIN;
  const expectedAud = c.env.CF_ACCESS_AUD;

  if (!teamDomain || !expectedAud) {
    return c.json({
      error: 'Cloudflare Access not configured',
      hint: 'Set CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD environment variables',
    }, 500);
  }

  // Get JWT from header or cookie
  const jwtHeader = c.req.header('CF-Access-JWT-Assertion');
  const jwtCookie = c.req.raw.headers.get('Cookie')
    ?.split(';')
    .find(cookie => cookie.trim().startsWith('CF_Authorization='))
    ?.split('=')[1];

  const jwt = jwtHeader || jwtCookie;

  if (!jwt) {
    return c.json({
      error: 'Unauthorized',
      hint: 'Missing Cloudflare Access JWT. Ensure this route is protected by Cloudflare Access.',
    }, 401);
  }

  try {
    const payload = await verifyAccessJWT(jwt, teamDomain, expectedAud);
    c.set('accessUser', { email: payload.email, name: payload.name });
    await next();
  } catch (err) {
    console.error('Access JWT verification failed:', err);
    return c.json({
      error: 'Unauthorized',
      details: err instanceof Error ? err.message : 'JWT verification failed',
    }, 401);
  }
});
app.route('/debug', debug);

// All other routes: start clawdbot and proxy
app.all('*', async (c) => {
  const sandbox = c.get('sandbox');
  const request = c.req.raw;
  const url = new URL(request.url);

  // Ensure clawdbot is running (this will wait for startup)
  try {
    await ensureClawdbotGateway(sandbox, c.env);
  } catch (error) {
    console.error('Failed to start Clawdbot:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';

    let hint = 'Check worker logs with: wrangler tail';
    if (!c.env.ANTHROPIC_API_KEY) {
      hint = 'ANTHROPIC_API_KEY is not set. Run: wrangler secret put ANTHROPIC_API_KEY';
    } else if (errorMessage.includes('heap out of memory') || errorMessage.includes('OOM')) {
      hint = 'Gateway ran out of memory. Try again or check for memory leaks.';
    }

    return c.json({
      error: 'Clawdbot gateway failed to start',
      details: errorMessage,
      hint,
    }, 503);
  }

  // Proxy to Clawdbot
  if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
    console.log('Proxying WebSocket connection to Clawdbot');
    console.log('WebSocket URL:', request.url);
    console.log('WebSocket search params:', url.search);
    return sandbox.wsConnect(request, CLAWDBOT_PORT);
  }

  console.log('Proxying HTTP request:', url.pathname + url.search);
  return sandbox.containerFetch(request, CLAWDBOT_PORT);
});

export default app;
