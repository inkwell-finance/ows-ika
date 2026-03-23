/**
 * Core types for the OWS-Ika adapter.
 *
 * Maps Ika 2PC-MPC dWallet primitives into OpenWallet Standard concepts.
 * The key difference from standard OWS: instead of storing a BIP-39 mnemonic
 * or raw private key, we store an encrypted user share of a threshold key.
 */

// ─── Chain & Curve Mapping ───────────────────────────────────────────────────

export enum IkaCurve {
  SECP256K1 = 0,
  SECP256R1 = 1,
  ED25519 = 2,
  RISTRETTO = 3,
}

export enum SignatureAlgorithm {
  ECDSASecp256k1 = 0,
  Taproot = 1,
  ECDSASecp256r1 = 2,
  EdDSA = 3,
  SchnorrkelSubstrate = 4,
}

export enum HashScheme {
  KECCAK256 = 0,
  SHA256 = 1,
  DoubleSHA256 = 2,
  SHA512 = 3,
  Merlin = 4,
}

export const CURVE_TO_CAIP: Record<IkaCurve, string[]> = {
  [IkaCurve.SECP256K1]: [
    'eip155:1',     // Ethereum
    'eip155:137',   // Polygon
    'eip155:42161', // Arbitrum
    'eip155:10',    // Optimism
    'eip155:8453',  // Base
    'eip155:56',    // BSC
    'bip122:000000000019d6689c085ae165831e93', // Bitcoin mainnet
    'sui:mainnet',
  ],
  [IkaCurve.SECP256R1]: [],
  [IkaCurve.ED25519]: [
    'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', // Solana mainnet
    'aptos:1',
  ],
  [IkaCurve.RISTRETTO]: [
    'polkadot:91b171bb158e2d3848fa23a9f1c25182', // Polkadot
  ],
};

// ─── DWallet Descriptor ──────────────────────────────────────────────────────

export type DWalletKind = 'zero-trust' | 'shared' | 'imported-key' | 'imported-key-shared';

export interface DWalletAccount {
  chainId: string;         // CAIP-2
  address: string;         // chain-native address derived from dWallet public key
  accountId: string;       // CAIP-10: `${chainId}:${address}`
}

/**
 * Extends OWS WalletDescriptor for Ika dWallets.
 * Instead of a mnemonic-backed HD wallet, this represents a single
 * threshold key that can sign for multiple chains (same curve).
 */
export interface IkaDWalletDescriptor {
  owsVersion: 2;
  id: string;                          // UUID for OWS, maps to dWallet object ID on Sui
  name: string;
  createdAt: string;                   // ISO 8601
  dwalletId: string;                   // on-chain object ID
  dwalletCapId: string;                // DWalletCap object ID (ownership proof)
  curve: IkaCurve;
  kind: DWalletKind;
  accounts: DWalletAccount[];          // derived chain addresses
  metadata: Record<string, unknown>;
}

// ─── Encrypted Share Storage ─────────────────────────────────────────────────

/**
 * The encrypted user share stored in the OWS vault.
 * Replaces the standard OWS `crypto` block which holds a mnemonic.
 *
 * The share is doubly encrypted:
 * 1. Ika's class-groups encryption (encrypted_centralized_secret_share_and_proof)
 * 2. OWS vault encryption (AES-256-GCM with scrypt/HKDF key derivation)
 */
export interface IkaShareCrypto {
  cipher: 'aes-256-gcm';
  cipherparams: { iv: string };
  ciphertext: string;                  // AES-encrypted IkaSharePayload
  authTag: string;
  kdf: 'scrypt' | 'hkdf-sha256';
  kdfparams: ScryptParams | HkdfParams;
}

export interface ScryptParams {
  dklen: 32;
  n: number;    // >= 65536
  r: 8;
  p: 1;
  salt: string;
}

export interface HkdfParams {
  dklen: 32;
  salt: string;
  info: 'ows-ika-api-key-v1';
}

/**
 * The plaintext payload inside the AES ciphertext.
 * Contains everything needed to participate in signing ceremonies.
 */
export interface IkaSharePayload {
  encryptionKey: Uint8Array;           // class-groups public key
  decryptionKey: Uint8Array;           // class-groups private key
  signingSecretKey: string;            // Ed25519 secret key (for share auth)
  encryptedShareId: string;            // on-chain EncryptedUserSecretKeyShare ID
  publicOutput: Uint8Array;            // from dWallet DKG (for key derivation)
}

/**
 * Complete OWS-Ika wallet file (persisted to ~/.ows/wallets/<id>.json).
 */
export interface IkaWalletFile {
  owsVersion: 2;
  id: string;
  name: string;
  createdAt: string;
  keyType: 'ika-2pc-mpc';             // distinguishes from standard OWS wallets
  dwalletId: string;
  dwalletCapId: string;
  curve: IkaCurve;
  kind: DWalletKind;
  accounts: DWalletAccount[];
  crypto: IkaShareCrypto;
  metadata: Record<string, unknown>;
}

// ─── Signing Types ───────────────────────────────────────────────────────────

export interface IkaSignRequest {
  walletId: string;
  chainId: string;                     // CAIP-2, resolved to curve + hash
  message: Uint8Array;                 // raw bytes to sign
  hashScheme?: HashScheme;             // override auto-detected hash
  signatureAlgorithm?: SignatureAlgorithm;
}

export interface IkaSignAndSendRequest extends IkaSignRequest {
  rpcUrl?: string;                     // chain RPC for broadcast
}

export interface IkaSignResult {
  signature: Uint8Array;               // raw r||s (64 bytes for ECDSA)
  recoveryId?: number;
  signSessionId: string;               // on-chain sign session for audit
}

export interface IkaSignAndSendResult extends IkaSignResult {
  transactionHash: string;
}

// ─── Presign Types ───────────────────────────────────────────────────────────

export interface PresignPool {
  walletId: string;
  presigns: PresignEntry[];
}

export interface PresignEntry {
  presignId: string;                   // on-chain PresignSession ID
  verifiedCapId?: string;              // VerifiedPresignCap ID (after verification)
  state: 'requested' | 'completed' | 'verified' | 'consumed' | 'rejected';
  createdAt: string;
}

// ─── Policy Types ────────────────────────────────────────────────────────────

/**
 * Dual policy evaluation result.
 * Both OWS local policy and Ika on-chain policy must allow.
 */
export interface DualPolicyResult {
  allowed: boolean;
  owsPolicyResult: PolicyLayerResult;
  ikaPolicyResult: PolicyLayerResult;
}

export interface PolicyLayerResult {
  allowed: boolean;
  reason?: string;
  policyId?: string;
}

/**
 * OWS policy file extended with Ika-specific rule types.
 */
export interface IkaPolicyRule {
  type: 'allowed_chains' | 'allowed_destinations' | 'daily_limit' | 'expires_at' | 'ika_policy_ref';
  chainIds?: string[];                 // for allowed_chains
  destinations?: string[];             // for allowed_destinations (contract addresses)
  limitWei?: string;                   // for daily_limit
  timestamp?: string;                  // for expires_at
  ikaPolicyId?: string;                // for ika_policy_ref (on-chain policy object)
}

export interface IkaPolicyFile {
  id: string;
  name: string;
  version: 1;
  createdAt: string;
  rules: IkaPolicyRule[];
  executable?: string;
  action: 'deny';
}

// ─── Chain Resolution ────────────────────────────────────────────────────────

export interface ChainConfig {
  caipId: string;
  curve: IkaCurve;
  signatureAlgorithm: SignatureAlgorithm;
  hashScheme: HashScheme;
  coinType: number;                    // BIP-44 coin type
  addressDerivation: (publicKey: Uint8Array) => string;
}
