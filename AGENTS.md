# AGENTS.md

## Cursor Cloud specific instructions

This is a **React Native Turbo Module library** (`rn-encryption`) providing cross-platform encryption (AES, RSA, ECDSA, SHA, HMAC, Base64, file encryption). It is **not a standalone application** — the `example/` directory contains a React Native example app for on-device testing, but the library itself is the primary development target.

### Key development commands

All commands are documented in `CONTRIBUTING.md` and `package.json` scripts. Quick reference:

- `yarn lint` — ESLint (0 errors expected; 2 inline-style warnings in example app are pre-existing)
- `yarn typecheck` — TypeScript type-checking
- `yarn test` — Jest unit tests
- `yarn prepare` — Build the library (CJS, ESM, TS declarations, codegen) via `react-native-builder-bob`

### Environment notes

- **Node.js v18** is required (see `.nvmrc`). Use `nvm use 18` before running commands.
- **Yarn 3.6.1** (Berry) is bundled in `.yarn/releases/yarn-3.6.1.cjs`. Do not use npm.
- The example app (`example/`) requires iOS/Android SDKs and simulators/emulators which are not available in the Cloud Agent VM. Library-level verification (lint, typecheck, test, build) is sufficient for CI-like validation.
- The `web-secure-encryption` dependency provides the web implementation and can be exercised in Node.js by polyfilling `globalThis.crypto` with `require('crypto').webcrypto`.
- Pre-commit hooks are configured via `lefthook.yml` (runs lint + typecheck on staged files).
