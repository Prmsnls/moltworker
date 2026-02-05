import type { Sandbox } from '@cloudflare/sandbox';
import type { TenantConfigDO, TenantRuntimeConfig } from './platform/tenantConfig';

/**
 * Environment bindings for the Moltbot Worker
 */
export interface MoltbotEnv {
  Sandbox: DurableObjectNamespace<Sandbox>;
  ASSETS: Fetcher; // Assets binding for admin UI static files
  MOLTBOT_BUCKET?: R2Bucket; // R2 bucket for persistent storage (optional)

  // Multi-tenant platform mode
  PLATFORM_MODE?: string; // 'true' to enable multi-tenant platform behavior
  PLATFORM_ADMIN_TOKEN?: string; // Bearer token for /__platform/* routes
  PUBLIC_DOMAIN?: string; // e.g. workers.openputer.com
  TENANT_CONFIG?: DurableObjectNamespace<TenantConfigDO>;

  // AI Gateway configuration (preferred)
  AI_GATEWAY_API_KEY?: string; // API key for the provider configured in AI Gateway
  AI_GATEWAY_BASE_URL?: string; // AI Gateway URL

  // Legacy direct provider configuration (fallback)
  ANTHROPIC_API_KEY?: string;
  ANTHROPIC_BASE_URL?: string;
  OPENAI_API_KEY?: string;
  OPENROUTER_API_KEY?: string;
  MOLTBOT_GATEWAY_TOKEN?: string; // Gateway token (mapped to CLAWDBOT_GATEWAY_TOKEN for container)

  CLAWDBOT_BIND_MODE?: string;
  DEV_MODE?: string; // 'true' skips CF Access auth + device pairing
  E2E_TEST_MODE?: string; // 'true' skips CF Access auth but keeps device pairing
  DEBUG_ROUTES?: string; // 'true' enables /debug/* routes
  SANDBOX_SLEEP_AFTER?: string; // 'never' (default) or duration like '10m'
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_DM_POLICY?: string;
  DISCORD_BOT_TOKEN?: string;
  DISCORD_DM_POLICY?: string;
  SLACK_BOT_TOKEN?: string;
  SLACK_APP_TOKEN?: string;

  // Cloudflare Access configuration for admin routes
  CF_ACCESS_TEAM_DOMAIN?: string;
  CF_ACCESS_AUD?: string;

  // R2 credentials for bucket mounting (set via wrangler secret)
  R2_ACCESS_KEY_ID?: string;
  R2_SECRET_ACCESS_KEY?: string;
  CF_ACCOUNT_ID?: string;

  // Browser Rendering binding for CDP shim
  BROWSER?: Fetcher;
  CDP_SECRET?: string;
  WORKER_URL?: string;
}

/**
 * Authenticated user from Cloudflare Access
 */
export interface AccessUser {
  email: string;
  name?: string;
}

/**
 * Hono app environment type
 */
export type AppEnv = {
  Bindings: MoltbotEnv;
  Variables: {
    sandbox: Sandbox;
    accessUser?: AccessUser;
    tenantSlug?: string;
    tenantConfig?: TenantRuntimeConfig;
  };
};

/**
 * JWT payload from Cloudflare Access
 */
export interface JWTPayload {
  aud: string[];
  email: string;
  exp: number;
  iat: number;
  iss: string;
  name?: string;
  sub: string;
  type: string;
}
