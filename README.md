# Clawdbot in Cloudflare Sandbox

Run [Clawdbot](https://clawd.bot/) personal AI assistant in a Cloudflare Sandbox.

## Quick Start

```bash
# Install dependencies
npm install

# Set your Anthropic API key
npx wrangler secret put ANTHROPIC_API_KEY

# Deploy
npm run deploy
```

Open the deployed Worker URL in your browser to access the Clawdbot Control UI.

## Authentication

By default, clawdbot uses **device pairing** for authentication. When a new device (browser, CLI, etc.) connects, it must be approved via the admin UI at `/_admin/`.

### Device Pairing (Default - Recommended for Production)

1. A device connects to the gateway
2. The connection is held pending until approved
3. An admin approves the device via `/_admin/`
4. The device is now paired and can connect freely

This is the most secure option as it requires explicit approval for each device.

### Token Authentication (Optional)

For automated access (e.g., CLI tools, scripts), you can set a gateway token:

```bash
npx wrangler secret put CLAWDBOT_GATEWAY_TOKEN
```

When a token is set, clients can authenticate by passing the token as a query parameter:

```
https://your-worker.workers.dev/?token=YOUR_TOKEN
wss://your-worker.workers.dev/ws?token=YOUR_TOKEN
```

**Important:** Even with a token, device pairing is still required in production. The token allows connections to proceed, but the Control UI will still require device approval unless you're in local dev mode.

For local development only, set `CLAWDBOT_DEV_MODE=true` in `.dev.vars` to enable `allowInsecureAuth`, which bypasses device pairing entirely.

## Cloudflare Access (Authentication)

The admin UI (`/_admin/`), API routes (`/api/*`), and debug routes (`/debug/*`) are protected by Cloudflare Access. To enable authentication:

### 1. Create a Cloudflare Access Application

1. Go to [Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com/)
2. Navigate to **Access** > **Applications**
3. Create a new **Self-hosted** application
4. Set the application domain to your Worker URL (e.g., `clawdbot-sandbox.your-subdomain.workers.dev`)
5. Add paths to protect: `/_admin/*`, `/api/*`, `/debug/*`
6. Configure your desired identity providers (e.g., email OTP, Google, GitHub)
7. Copy the **Application Audience (AUD)** tag from the application settings

### 2. Set Secrets

```bash
# Your Cloudflare Access team domain (e.g., "myteam.cloudflareaccess.com")
npx wrangler secret put CF_ACCESS_TEAM_DOMAIN

# The Application Audience (AUD) tag from your Access application
npx wrangler secret put CF_ACCESS_AUD
```

### Local Development

For local development, create a `.dev.vars` file with:

```bash
LOCAL_DEV=true              # Skip Cloudflare Access authentication
CLAWDBOT_DEV_MODE=true      # Enable allowInsecureAuth (bypasses device pairing)
```

## Persistent Storage (R2)

By default, clawdbot data (configs, paired devices, conversation history) is lost when the container restarts. To enable persistent storage across sessions, configure R2:

### 1. Create R2 API Token

1. Go to **R2** > **Overview** in the [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Click **Manage R2 API Tokens**
3. Create a new token with **Object Read & Write** permissions
4. Select the `clawdbot-data` bucket (created automatically on first deploy)
5. Copy the **Access Key ID** and **Secret Access Key**

### 2. Set Secrets

```bash
# R2 Access Key ID
npx wrangler secret put AWS_ACCESS_KEY_ID

# R2 Secret Access Key
npx wrangler secret put AWS_SECRET_ACCESS_KEY

# Your Cloudflare Account ID (found in dashboard URL or R2 overview)
npx wrangler secret put CF_ACCOUNT_ID
```

### How It Works

When R2 credentials are configured:
- The R2 bucket is mounted at `/data/clawdbot` in the container
- Clawdbot uses this directory for all its state via `CLAWDBOT_STATE_DIR`
- All data persists across container restarts and redeployments

Without R2 credentials, clawdbot still works but uses ephemeral storage.

## Admin UI

Access the admin UI at `/_admin/` to:
- **Restart Gateway** - Kill and restart the clawdbot gateway process
- View pending device pairing requests
- Approve devices individually or all at once
- View paired devices

The admin UI requires Cloudflare Access authentication (or `LOCAL_DEV=true` for local development).

## Debug Endpoints

Debug endpoints are available at `/debug/*` (requires Cloudflare Access):

- `GET /debug/processes` - List all container processes
- `GET /debug/logs?id=<process_id>` - Get logs for a specific process
- `GET /debug/version` - Get container and clawdbot version info

## Optional: Chat Channels

### Telegram

```bash
npx wrangler secret put TELEGRAM_BOT_TOKEN
npm run deploy
```

### Discord

```bash
npx wrangler secret put DISCORD_BOT_TOKEN
npm run deploy
```

### Slack

```bash
npx wrangler secret put SLACK_BOT_TOKEN
npx wrangler secret put SLACK_APP_TOKEN
npm run deploy
```

## All Secrets Reference

| Secret | Required | Description |
|--------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Your Anthropic API key |
| `CLAWDBOT_GATEWAY_TOKEN` | No | Gateway token for authentication (pass via `?token=` query param) |
| `CLAWDBOT_DEV_MODE` | No | Set to `true` to enable `allowInsecureAuth` (local dev only) |
| `CF_ACCESS_TEAM_DOMAIN` | Recommended | Cloudflare Access team domain |
| `CF_ACCESS_AUD` | Recommended | Cloudflare Access application audience |
| `AWS_ACCESS_KEY_ID` | No | R2 access key for persistent storage |
| `AWS_SECRET_ACCESS_KEY` | No | R2 secret key for persistent storage |
| `CF_ACCOUNT_ID` | No | Cloudflare account ID for R2 |
| `TELEGRAM_BOT_TOKEN` | No | Telegram bot token |
| `DISCORD_BOT_TOKEN` | No | Discord bot token |
| `SLACK_BOT_TOKEN` | No | Slack bot token |
| `SLACK_APP_TOKEN` | No | Slack app token |

## Troubleshooting

**Gateway fails to start:** Check `npx wrangler secret list` and `npx wrangler tail`

**Config changes not working:** Edit the `# Build cache bust:` comment in `Dockerfile` and redeploy

**Slow first request:** Cold starts take 1-2 minutes. Subsequent requests are faster.

**R2 not mounting:** Check that all three R2 secrets are set (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `CF_ACCOUNT_ID`). Note: R2 mounting only works in production, not with `wrangler dev`.

**Access denied on admin routes:** Ensure `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_AUD` are set, and that your Cloudflare Access application is configured correctly.

## Links

- [Clawdbot](https://clawd.bot/)
- [Clawdbot Docs](https://docs.clawd.bot)
- [Cloudflare Sandbox Docs](https://developers.cloudflare.com/sandbox/)
- [Cloudflare Access Docs](https://developers.cloudflare.com/cloudflare-one/policies/access/)
