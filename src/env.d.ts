/// <reference types="@cloudflare/workers-types" />

import type { Sandbox } from '@cloudflare/sandbox';

// Allow importing HTML files as strings
declare module '*.html' {
  const content: string;
  export default content;
}

// Allow importing CSS files as strings
declare module '*.css' {
  const content: string;
  export default content;
}

// Allow importing JS files as strings
declare module '*.js' {
  const content: string;
  export default content;
}

declare global {
  interface Env {
    Sandbox: DurableObjectNamespace<Sandbox>;
    ANTHROPIC_API_KEY?: string;
    OPENAI_API_KEY?: string;
    CLAWDBOT_GATEWAY_TOKEN?: string;
    TELEGRAM_BOT_TOKEN?: string;
    TELEGRAM_DM_POLICY?: string;
    DISCORD_BOT_TOKEN?: string;
    DISCORD_DM_POLICY?: string;
    SLACK_BOT_TOKEN?: string;
    SLACK_APP_TOKEN?: string;
  }
}

export {};
