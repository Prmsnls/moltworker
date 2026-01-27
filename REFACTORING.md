# Testing & Refactoring Plan

## Current State Analysis

The codebase has a single 964-line `src/index.ts` file containing:
- Type definitions
- Helper functions (env vars, process management, R2 mounting)
- JWT/Cloudflare Access authentication logic
- API routes (devices, gateway)
- Debug routes
- Admin UI routes
- Main app with proxy logic

**Key Issues:**
1. **Monolithic file** - Everything in one file makes testing difficult
2. **Duplicated auth middleware** - Same JWT verification logic repeated 3 times (api, admin, debug routes)
3. **No test infrastructure** - No test framework or tests
4. **Tightly coupled** - Sandbox interactions mixed with business logic
5. **Global state** - `jwksCache` is a module-level variable

---

## Refactoring Plan

### Phase 1: Extract Modules

```
src/
├── index.ts              # Main app entry, route mounting only
├── types.ts              # All type definitions (ClawdbotEnv, AppEnv, etc.)
├── config.ts             # Constants (CLAWDBOT_PORT, STARTUP_TIMEOUT_MS, etc.)
├── auth/
│   ├── index.ts          # Re-exports
│   ├── jwt.ts            # JWT verification (base64UrlDecode, verifyAccessJWT)
│   ├── jwks.ts           # JWKS fetching and caching
│   └── middleware.ts     # Reusable CF Access middleware factory
├── gateway/
│   ├── index.ts          # Re-exports
│   ├── process.ts        # findExistingClawdbotProcess, ensureClawdbotGateway
│   ├── env.ts            # buildEnvVars
│   └── r2.ts             # mountR2Storage
├── routes/
│   ├── api.ts            # /api/* routes
│   ├── admin.ts          # /_admin/* routes
│   ├── debug.ts          # /debug/* routes
│   └── proxy.ts          # Catch-all proxy route
└── client/               # (unchanged - React admin UI)
```

### Phase 2: Create Reusable Auth Middleware

Extract the duplicated auth logic into a factory function:

```typescript
// src/auth/middleware.ts
export function createAccessMiddleware(options: {
  type: 'json' | 'html';
  redirectOnMissing?: boolean;
}) { ... }
```

### Phase 3: Add Dependency Injection

Make sandbox interactions injectable for testing:

```typescript
// Instead of directly using sandbox, pass it as a parameter
// This allows mocking in tests
```

---

## Test Plan

### Test Framework Setup

Install Vitest (works well with Vite):
```bash
npm install -D vitest @vitest/coverage-v8
```

### Unit Tests

| Module | Test File | What to Test |
|--------|-----------|--------------|
| `auth/jwt.ts` | `auth/jwt.test.ts` | `base64UrlDecode`, `verifyAccessJWT` (valid/invalid/expired tokens) |
| `auth/jwks.ts` | `auth/jwks.test.ts` | JWKS fetching, caching behavior, TTL expiration |
| `gateway/env.ts` | `gateway/env.test.ts` | `buildEnvVars` with various env configurations |
| `gateway/process.ts` | `gateway/process.test.ts` | `findExistingClawdbotProcess` with mock process lists |
| `gateway/r2.ts` | `gateway/r2.test.ts` | `mountR2Storage` success/failure cases |

### Integration Tests

| Test File | What to Test |
|-----------|--------------|
| `routes/api.test.ts` | API endpoints with mocked sandbox |
| `routes/admin.test.ts` | Admin routes serve correct assets |
| `routes/proxy.test.ts` | Proxy behavior for HTTP and WebSocket |
| `auth/middleware.test.ts` | Auth middleware behavior (local dev, missing JWT, valid JWT) |

### Test Cases Detail

**auth/jwt.test.ts:**
```typescript
describe('base64UrlDecode', () => {
  it('decodes standard base64url strings')
  it('handles padding correctly')
  it('replaces URL-safe characters')
})

describe('verifyAccessJWT', () => {
  it('rejects malformed JWT (wrong number of parts)')
  it('rejects JWT with missing kid')
  it('rejects JWT with unknown signing key')
  it('rejects JWT with invalid signature')
  it('rejects expired JWT')
  it('rejects JWT with wrong audience')
  it('rejects JWT with wrong issuer')
  it('accepts valid JWT and returns payload')
})
```

**gateway/env.test.ts:**
```typescript
describe('buildEnvVars', () => {
  it('returns empty object when no env vars set')
  it('includes ANTHROPIC_API_KEY when set')
  it('includes all channel tokens when set')
  it('sets R2 paths when r2Mounted is true')
  it('does not set R2 paths when r2Mounted is false')
})
```

**gateway/process.test.ts:**
```typescript
describe('findExistingClawdbotProcess', () => {
  it('returns null when no processes exist')
  it('returns null when only CLI commands are running')
  it('returns gateway process when running')
  it('returns gateway process when starting')
  it('ignores completed/failed processes')
  it('handles listProcesses errors gracefully')
})
```

**routes/api.test.ts:**
```typescript
describe('GET /api/devices', () => {
  it('returns 401 without auth')
  it('returns 500 when CF Access not configured')
  it('returns device list on success')
  it('handles parse errors gracefully')
})

describe('POST /api/devices/:requestId/approve', () => {
  it('returns 400 without requestId')
  it('returns success on approval')
})

describe('POST /api/gateway/restart', () => {
  it('kills existing process and starts new one')
  it('starts new process when none exists')
})
```

---

## Implementation Order

1. **Set up test infrastructure** (vitest, test script in package.json)
2. **Write tests for existing code** (without refactoring yet)
3. **Extract `types.ts` and `config.ts`** (simple, low risk)
4. **Extract and test `auth/` modules**
5. **Extract and test `gateway/` modules**
6. **Extract routes** with reusable auth middleware
7. **Clean up `index.ts`** to be just route mounting

---

## Progress Tracking

- [ ] Set up Vitest
- [ ] Extract `types.ts` and `config.ts`
- [ ] Extract `auth/` modules with tests
- [ ] Extract `gateway/` modules with tests
- [ ] Extract routes with reusable auth middleware
- [ ] Clean up `index.ts`
