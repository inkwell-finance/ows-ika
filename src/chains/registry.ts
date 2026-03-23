import {
  type ChainConfig,
  HashScheme,
  IkaCurve,
  SignatureAlgorithm,
} from '../types.js';

const keccak256Address = (_publicKey: Uint8Array): string => {
  // Keccak256(uncompressed pubkey[1:]) -> last 20 bytes -> EIP-55 checksum
  throw new Error('EVM address derivation requires keccak256 — install a crypto provider');
};

const base58Address = (_publicKey: Uint8Array): string => {
  // Ed25519 pubkey IS the Solana address (base58 encoded)
  throw new Error('Solana address derivation requires base58 — install a crypto provider');
};

const suiAddress = (_publicKey: Uint8Array): string => {
  // BLAKE2b-256([flag_byte] || compressed_pubkey) -> 0x hex
  throw new Error('Sui address derivation requires blake2b — install a crypto provider');
};

export const CHAIN_REGISTRY: Record<string, ChainConfig> = {
  // ─── EVM ───────────────────────────────────────────────────────────
  'eip155:1': {
    caipId: 'eip155:1',
    curve: IkaCurve.SECP256K1,
    signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
    hashScheme: HashScheme.KECCAK256,
    coinType: 60,
    addressDerivation: keccak256Address,
  },
  'eip155:8453': {
    caipId: 'eip155:8453',
    curve: IkaCurve.SECP256K1,
    signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
    hashScheme: HashScheme.KECCAK256,
    coinType: 60,
    addressDerivation: keccak256Address,
  },
  'eip155:137': {
    caipId: 'eip155:137',
    curve: IkaCurve.SECP256K1,
    signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
    hashScheme: HashScheme.KECCAK256,
    coinType: 60,
    addressDerivation: keccak256Address,
  },
  'eip155:42161': {
    caipId: 'eip155:42161',
    curve: IkaCurve.SECP256K1,
    signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
    hashScheme: HashScheme.KECCAK256,
    coinType: 60,
    addressDerivation: keccak256Address,
  },
  'eip155:10': {
    caipId: 'eip155:10',
    curve: IkaCurve.SECP256K1,
    signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
    hashScheme: HashScheme.KECCAK256,
    coinType: 60,
    addressDerivation: keccak256Address,
  },

  // ─── Solana ────────────────────────────────────────────────────────
  'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp': {
    caipId: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
    curve: IkaCurve.ED25519,
    signatureAlgorithm: SignatureAlgorithm.EdDSA,
    hashScheme: HashScheme.SHA512,
    coinType: 501,
    addressDerivation: base58Address,
  },

  // ─── Sui ───────────────────────────────────────────────────────────
  'sui:mainnet': {
    caipId: 'sui:mainnet',
    curve: IkaCurve.SECP256K1,
    signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
    hashScheme: HashScheme.SHA256,
    coinType: 784,
    addressDerivation: suiAddress,
  },
};

const CHAIN_ALIASES: Record<string, string> = {
  ethereum: 'eip155:1',
  base: 'eip155:8453',
  polygon: 'eip155:137',
  arbitrum: 'eip155:42161',
  optimism: 'eip155:10',
  solana: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
  sui: 'sui:mainnet',
};

export function resolveChain(chainIdOrAlias: string): ChainConfig {
  const caipId = CHAIN_ALIASES[chainIdOrAlias.toLowerCase()] ?? chainIdOrAlias;
  const config = CHAIN_REGISTRY[caipId];
  if (!config) {
    throw new Error(`Unsupported chain: ${chainIdOrAlias} (resolved to ${caipId})`);
  }
  return config;
}

export function chainsForCurve(curve: IkaCurve): ChainConfig[] {
  return Object.values(CHAIN_REGISTRY).filter((c) => c.curve === curve);
}
