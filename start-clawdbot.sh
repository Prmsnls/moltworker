#!/bin/bash
# Startup script for Clawdbot in Cloudflare Sandbox
# This script configures clawdbot from environment variables and starts the gateway
#
# When R2 storage is mounted, CLAWDBOT_STATE_DIR and CLAWDBOT_CONFIG_PATH will be set
# to point to the mounted directory for persistent storage across sessions.

set -e

# Check if clawdbot gateway is already running - bail early if so
if pgrep -f "clawdbot gateway" > /dev/null 2>&1; then
    echo "Clawdbot gateway is already running, exiting."
    exit 0
fi

# Use CLAWDBOT_STATE_DIR if set (R2 mounted), otherwise default to /root/.clawdbot
CONFIG_DIR="${CLAWDBOT_STATE_DIR:-/root/.clawdbot}"
CONFIG_FILE="${CLAWDBOT_CONFIG_PATH:-$CONFIG_DIR/clawdbot.json}"
TEMPLATE_DIR="/root/.clawdbot-templates"
TEMPLATE_FILE="$TEMPLATE_DIR/clawdbot.json.template"

echo "Config directory: $CONFIG_DIR"
echo "Config file: $CONFIG_FILE"

# Create config directory if it doesn't exist (may already exist from R2 mount)
mkdir -p "$CONFIG_DIR"

# If config file doesn't exist (fresh R2 mount or first run), create from template
if [ ! -f "$CONFIG_FILE" ]; then
    echo "No existing config found, initializing from template..."
    if [ -f "$TEMPLATE_FILE" ]; then
        cp "$TEMPLATE_FILE" "$CONFIG_FILE"
    else
        # Create minimal config if template doesn't exist (new config format)
        cat > "$CONFIG_FILE" << 'EOFCONFIG'
{
  "agents": {
    "defaults": {
      "workspace": "/root/clawd",
      "model": {
        "primary": "anthropic/claude-sonnet-4-20250514"
      }
    }
  },
  "gateway": {
    "port": 18789,
    "mode": "local"
  }
}
EOFCONFIG
    fi
else
    echo "Using existing config from persistent storage"
fi

# Use Node.js for JSON manipulation since jq might not be available
node << EOFNODE
const fs = require('fs');

const configPath = process.env.CLAWDBOT_CONFIG_PATH || '/root/.clawdbot/clawdbot.json';
console.log('Updating config at:', configPath);
let config = {};

try {
    config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
} catch (e) {
    console.log('Starting with empty config');
}

// Ensure nested objects exist (new config format)
config.agents = config.agents || {};
config.agents.defaults = config.agents.defaults || {};
config.agents.defaults.model = config.agents.defaults.model || {};
config.gateway = config.gateway || {};
config.channels = config.channels || {};

// Gateway configuration
config.gateway.port = 18789;
config.gateway.mode = 'local';

// Trust proxy headers from Cloudflare (10.x.x.x is the container network)
// This allows clawdbot to see the real client IP and treat connections appropriately
// Try multiple formats to find what clawdbot expects
config.gateway.trustedProxies = ['10.1.0.0'];

// Set gateway token if provided (use auth.token format)
if (process.env.CLAWDBOT_GATEWAY_TOKEN) {
    config.gateway.auth = config.gateway.auth || {};
    config.gateway.auth.token = process.env.CLAWDBOT_GATEWAY_TOKEN;
    config.gateway.auth.mode = 'token';  // Token-only auth (no device pairing)
}

// Only allow insecure auth for local dev (when CLAWDBOT_DEV_MODE=true)
// In production, device pairing is required even with token auth
if (process.env.CLAWDBOT_DEV_MODE === 'true') {
    config.gateway.controlUi = config.gateway.controlUi || {};
    config.gateway.controlUi.allowInsecureAuth = true;
}

// Telegram configuration
if (process.env.TELEGRAM_BOT_TOKEN) {
    config.channels.telegram = config.channels.telegram || {};
    config.channels.telegram.botToken = process.env.TELEGRAM_BOT_TOKEN;
    config.channels.telegram.enabled = true;
    
    // DM policy
    config.channels.telegram.dm = config.channels.telegram.dm || {};
    config.channels.telegram.dm.policy = process.env.TELEGRAM_DM_POLICY || 'pairing';
}

// Discord configuration
if (process.env.DISCORD_BOT_TOKEN) {
    config.channels.discord = config.channels.discord || {};
    config.channels.discord.token = process.env.DISCORD_BOT_TOKEN;
    config.channels.discord.enabled = true;
    
    config.channels.discord.dm = config.channels.discord.dm || {};
    config.channels.discord.dm.policy = process.env.DISCORD_DM_POLICY || 'pairing';
}

// Slack configuration
if (process.env.SLACK_BOT_TOKEN && process.env.SLACK_APP_TOKEN) {
    config.channels.slack = config.channels.slack || {};
    config.channels.slack.botToken = process.env.SLACK_BOT_TOKEN;
    config.channels.slack.appToken = process.env.SLACK_APP_TOKEN;
    config.channels.slack.enabled = true;
}

// Write updated config
fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
console.log('Configuration updated successfully');
console.log('Config:', JSON.stringify(config, null, 2));
EOFNODE

echo "Starting Clawdbot Gateway..."
echo "Gateway will be available on port 18789"

# Clean up stale lock files (process check already happened above)
rm -f /tmp/clawdbot-gateway.lock 2>/dev/null || true
rm -f /root/.clawdbot/gateway.lock 2>/dev/null || true

# Always bind to 0.0.0.0 (lan mode) since Worker connects via container network
BIND_MODE="lan"
echo "Dev mode: ${CLAWDBOT_DEV_MODE:-false}, Bind mode: $BIND_MODE"

# Start the gateway
# If CLAWDBOT_GATEWAY_TOKEN is set, use token auth (skips device pairing)
# If not set, rely on device pairing for authentication
if [ -n "$CLAWDBOT_GATEWAY_TOKEN" ]; then
    echo "Starting gateway with token auth..."
    exec clawdbot gateway --port 18789 --verbose --allow-unconfigured --bind "$BIND_MODE" --token "$CLAWDBOT_GATEWAY_TOKEN"
else
    echo "Starting gateway with device pairing (no token)..."
    exec clawdbot gateway --port 18789 --verbose --allow-unconfigured --bind "$BIND_MODE"
fi
