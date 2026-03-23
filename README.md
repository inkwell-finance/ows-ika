# OWS-Ika

OpenWallet Standard adapter for [Ika](https://ika.xyz) 2PC-MPC dWallets.

Policy-gated threshold signing for AI agents. No single party holds a complete key.

## Why

OpenWallet Standard (OWS) defines how wallets store keys, enforce policies, and expose signing to agents. Ika's 2PC-MPC dWallets split private keys into two shares — one held locally, one held by the Ika network — so neither party can sign alone.

OWS-Ika bridges these two systems:

| Layer | Responsibility |
|-------|---------------|
| **OWS** | Local share custody, agent access (MCP/REST), pre-signing policy enforcement |
| **Ika** | Distributed threshold signing, on-chain policy enforcement (PolicyGatedDWalletCap) |

A signing request must pass **both** policy layers. Compromising one side is not enough.

## Architecture

The adapter supports two signing modes. The caller chooses the tradeoff.

### On-chain mode (trustless)

Policy enforcement and Ika signature request happen atomically in the same transaction on the policy chain. Neither can be bypassed without the other.

```
Agent (MCP/REST)
    ↓  request
OWS local policy engine ── deny? → stop
    ↓  allow
Decrypt user share + consume presign
    ↓
Compute user contribution (partial sig — useless alone)
    ↓
Submit to policy chain (e.g. Sui smart contract)
    ↓
Policy contract validates tx ── deny? → stop
    ↓  allow
Policy contract requests Ika signature (atomic, same tx)
    ↓
Ika co-signs → threshold signature produced
    ↓
Broadcast to target chain (EVM / Solana / Sui / ...)
```

### Off-chain mode (flexible)

The caller holds a raw `DWalletCap` and requests Ika's signature directly via the SDK. OWS local policies still apply, but on-chain policy enforcement is opt-in. Useful for development, low-latency operations, or cases where the caller is trusted.

```
Agent (MCP/REST)
    ↓  request
OWS local policy engine ── deny? → stop
    ↓  allow
Decrypt user share + consume presign
    ↓
Compute user contribution (partial sig — useless alone)
    ↓
Request Ika signature directly (off-chain SDK call)
    ↓
Ika co-signs → threshold signature produced
    ↓
Broadcast to target chain (EVM / Solana / Sui / ...)
```

### Which mode is available depends on the dWallet setup

| dWallet Kind | DWalletCap Holder | Available Modes | Typical Use |
|---|---|---|---|
| `zero-trust` | Policy contract (deposited) | On-chain only | Loans, vaults, protocol treasuries — cap is locked in the contract, only the contract can authorize |
| `zero-trust` | User/agent (raw cap) | Both | Self-custodied wallets — user can choose trustless or flexible |
| `shared` | Anyone (public share) | Both | Dev/testing, shared signing — user share is public, anyone can compute the partial sig |
| `imported-key` | User/agent | Off-chain only | Imported existing key into dWallet — typically no policy contract deployed |

The key insight: **who holds the `DWalletCap` determines who can authorize signing**. When a policy contract holds the cap (e.g. Leviathan's `PolicyGatedDWalletCap`), only the contract can call `approve_message` — forcing on-chain mode. When the user holds the cap directly, they choose.

> **Cap deposit is a one-way gate.** A dWallet starts with the user holding the cap (both modes available). When the user deposits the cap into a protocol's smart contract, off-chain mode becomes permanently unavailable — the contract now controls authorization, and only on-chain transactions through that contract can trigger signing. This is by design: depositing the cap is how you opt into trustless enforcement. The protocol defines what transactions are allowed, and neither the user nor an agent can bypass it. Think of it like handing your car keys to a valet with a GPS fence — you can still drive, but only where they allow.

## Modules

### Storage (`src/storage/`)

Extends the OWS vault format with a new key type: `ika-2pc-mpc`. Instead of storing a BIP-39 mnemonic, the vault holds the user's encrypted 2PC-MPC share — doubly encrypted:

1. **Ika class-groups encryption** (homomorphic, from DKG)
2. **OWS AES-256-GCM** with scrypt-derived key (passphrase) or HKDF-derived key (API token)

```typescript
import { createDWalletVault, unlockShare } from '@ows-ika/core/storage';

const wallet = await createDWalletVault({
  name: 'treasury',
  dwalletId: '0xabc...',
  dwalletCapId: '0xdef...',
  curve: IkaCurve.SECP256K1,
  kind: 'zero-trust',
  accounts: [{ chainId: 'eip155:8453', address: '0x...', accountId: 'eip155:8453:0x...' }],
  sharePayload: { encryptionKey, decryptionKey, signingSecretKey, encryptedShareId, publicOutput },
  passphrase: 'hunter2',
});

const share = await unlockShare(wallet.id, 'hunter2');
```

### Signing (`src/signing/`)

Bridges OWS `sign()` to Ika's 5-phase 2PC-MPC ceremony:

1. **Consume presign** — from local pool (pre-computed)
2. **Approve message** — on-chain proof of authorization
3. **Compute user contribution** — decrypt share, compute partial signature
4. **Request sign** — submit to Ika network
5. **Poll for signature** — network completes threshold signature

All Ika interaction goes through the `IkaClientAdapter` interface — no direct SDK dependency.

```typescript
import { sign } from '@ows-ika/core/signing';

const result = await sign(
  { walletId: wallet.id, chainId: 'eip155:8453', message: txBytes },
  { passphrase: 'hunter2', ikaClient: myIkaAdapter },
);
// result.signature — raw r||s bytes
// result.signSessionId — on-chain audit trail
```

### Policy (`src/policy/`)

Dual evaluation engine. OWS local policies run first (fast, in-process). If they pass, Ika on-chain policies are checked (RPC). First denial short-circuits.

```typescript
import { evaluateDualPolicy } from '@ows-ika/core/policy';

const result = await evaluateDualPolicy(
  request,
  ['spending-limit', 'base-only'],  // OWS policy IDs
  ikaPolicyAdapter,                  // checks PolicyGatedDWalletCap on Sui
  '0x_policy_object_id',
  wallet.dwalletId,
);

if (!result.allowed) {
  console.log('OWS:', result.owsPolicyResult);
  console.log('Ika:', result.ikaPolicyResult);
}
```

**OWS policy rules** (declarative, in JSON files under `~/.ows/policies/`):

| Rule | Effect |
|------|--------|
| `allowed_chains` | Restrict signing to specific CAIP-2 chains |
| `allowed_destinations` | Whitelist contract addresses |
| `daily_limit` | Cap daily spending (wei) |
| `expires_at` | Time-bound access |
| `ika_policy_ref` | Link to on-chain Ika policy for dual enforcement |

**Executable policies** also supported — subprocess receives `PolicyContext` on stdin, returns `{ "allow": true/false }`.

### Agent (`src/agent/`)

MCP server exposing 5 tools for AI agent wallet access:

| Tool | Description |
|------|-------------|
| `ows_ika_list_wallets` | List all Ika dWallets in the vault |
| `ows_ika_get_wallet` | Wallet details + presign availability |
| `ows_ika_sign` | Sign via 2PC-MPC (policy-checked) |
| `ows_ika_check_policy` | Dry-run policy evaluation |
| `ows_ika_presign_status` | Check available presigns |

```typescript
import { OwsIkaMcpServer } from '@ows-ika/core/agent';

const server = new OwsIkaMcpServer({
  ikaClient: myIkaAdapter,
  ikaPolicyAdapter: myPolicyAdapter,
  policyIds: ['spending-limit'],
});

// Register tools with your MCP framework
const tools = server.getToolDefinitions();
const result = await server.handleToolCall('ows_ika_sign', { walletId, chainId, messageHex, passphrase });
```

### Chains (`src/chains/`)

Maps CAIP-2 chain identifiers to Ika curves, signature algorithms, and hash schemes.

```typescript
import { resolveChain, chainsForCurve } from '@ows-ika/core/chains';

const base = resolveChain('base');           // alias → eip155:8453
const eth = resolveChain('eip155:1');        // full CAIP-2
const evmChains = chainsForCurve(IkaCurve.SECP256K1);
```

Supported chains: Ethereum, Base, Polygon, Arbitrum, Optimism, Solana, Sui, Bitcoin (see [registry.ts](src/chains/registry.ts)).

## Vault File Format

Stored at `~/.ows/wallets/<uuid>.json`:

```json
{
  "owsVersion": 2,
  "id": "3198bc9c-...",
  "name": "treasury",
  "createdAt": "2026-03-23T...",
  "keyType": "ika-2pc-mpc",
  "dwalletId": "0xabc...",
  "dwalletCapId": "0xdef...",
  "curve": 0,
  "kind": "zero-trust",
  "accounts": [
    { "chainId": "eip155:8453", "address": "0x...", "accountId": "eip155:8453:0x..." }
  ],
  "crypto": {
    "cipher": "aes-256-gcm",
    "cipherparams": { "iv": "..." },
    "ciphertext": "...",
    "authTag": "...",
    "kdf": "scrypt",
    "kdfparams": { "dklen": 32, "n": 65536, "r": 8, "p": 1, "salt": "..." }
  }
}
```

The `ciphertext` contains the encrypted `IkaSharePayload`: class-groups keys, Ed25519 signing key, encrypted share ID, and DKG public output.

## IkaClientAdapter

All Ika SDK interaction is behind an interface. Implement it to connect to a real Ika network:

```typescript
interface IkaClientAdapter {
  approveMessage(params)        → { messageApprovalId }
  computeUserSignMessage(params) → Uint8Array
  requestSign(params)           → { signSessionId }
  waitForSignature(params)      → { signature }
  getPresignData(presignId)     → Uint8Array
  decryptUserShare(params)      → { secretShare }
}
```

## Development

```bash
pnpm install
pnpm exec tsc --noEmit   # type-check
pnpm build                # compile to dist/
pnpm test                 # run tests
```

## License

MIT
