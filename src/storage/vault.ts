import { randomBytes, createCipheriv, createDecipheriv, scryptSync } from 'node:crypto';
import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type {
  IkaWalletFile,
  IkaDWalletDescriptor,
  IkaSharePayload,
  IkaShareCrypto,
  DWalletAccount,
  DWalletKind,
  IkaCurve,
} from '../types.js';

const OWS_DIR = join(homedir(), '.ows');
const WALLETS_DIR = join(OWS_DIR, 'wallets');

export interface CreateDWalletVaultOptions {
  name: string;
  dwalletId: string;
  dwalletCapId: string;
  curve: IkaCurve;
  kind: DWalletKind;
  accounts: DWalletAccount[];
  sharePayload: IkaSharePayload;
  passphrase: string;
  metadata?: Record<string, unknown>;
}

function encryptPayload(payload: IkaSharePayload, passphrase: string): IkaShareCrypto {
  const salt = randomBytes(32).toString('hex');
  const iv = randomBytes(12).toString('hex');

  const key = scryptSync(passphrase, Buffer.from(salt, 'hex'), 32, { N: 65536, r: 8, p: 1 });

  const plaintext = Buffer.from(JSON.stringify({
    encryptionKey: Array.from(payload.encryptionKey),
    decryptionKey: Array.from(payload.decryptionKey),
    signingSecretKey: payload.signingSecretKey,
    encryptedShareId: payload.encryptedShareId,
    publicOutput: Array.from(payload.publicOutput),
  }));

  const cipher = createCipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag().toString('hex');

  key.fill(0);

  return {
    cipher: 'aes-256-gcm',
    cipherparams: { iv },
    ciphertext: encrypted.toString('hex'),
    authTag,
    kdf: 'scrypt',
    kdfparams: { dklen: 32, n: 65536, r: 8, p: 1, salt },
  };
}

function decryptPayload(crypto: IkaShareCrypto, passphrase: string): IkaSharePayload {
  if (crypto.kdf !== 'scrypt') {
    throw new Error(`Unsupported KDF: ${crypto.kdf}`);
  }
  const params = crypto.kdfparams as { dklen: number; n: number; r: number; p: number; salt: string };
  const key = scryptSync(passphrase, Buffer.from(params.salt, 'hex'), params.dklen, {
    N: params.n,
    r: params.r,
    p: params.p,
  });

  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(crypto.cipherparams.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(crypto.authTag, 'hex'));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(crypto.ciphertext, 'hex')),
    decipher.final(),
  ]);

  key.fill(0);

  const parsed = JSON.parse(decrypted.toString('utf8'));
  return {
    encryptionKey: new Uint8Array(parsed.encryptionKey),
    decryptionKey: new Uint8Array(parsed.decryptionKey),
    signingSecretKey: parsed.signingSecretKey,
    encryptedShareId: parsed.encryptedShareId,
    publicOutput: new Uint8Array(parsed.publicOutput),
  };
}

export async function ensureVaultDirs(): Promise<void> {
  await mkdir(WALLETS_DIR, { recursive: true });
  await chmod(OWS_DIR, 0o700);
  await chmod(WALLETS_DIR, 0o700);
}

export async function createDWalletVault(opts: CreateDWalletVaultOptions): Promise<IkaDWalletDescriptor> {
  await ensureVaultDirs();

  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();

  const walletFile: IkaWalletFile = {
    owsVersion: 2,
    id,
    name: opts.name,
    createdAt,
    keyType: 'ika-2pc-mpc',
    dwalletId: opts.dwalletId,
    dwalletCapId: opts.dwalletCapId,
    curve: opts.curve,
    kind: opts.kind,
    accounts: opts.accounts,
    crypto: encryptPayload(opts.sharePayload, opts.passphrase),
    metadata: opts.metadata ?? {},
  };

  const filePath = join(WALLETS_DIR, `${id}.json`);
  await writeFile(filePath, JSON.stringify(walletFile, null, 2), 'utf8');
  await chmod(filePath, 0o600);

  return {
    owsVersion: 2,
    id,
    name: opts.name,
    createdAt,
    dwalletId: opts.dwalletId,
    dwalletCapId: opts.dwalletCapId,
    curve: opts.curve,
    kind: opts.kind,
    accounts: opts.accounts,
    metadata: opts.metadata ?? {},
  };
}

export async function loadWalletFile(walletId: string): Promise<IkaWalletFile> {
  const filePath = join(WALLETS_DIR, `${walletId}.json`);
  const raw = await readFile(filePath, 'utf8');
  const parsed = JSON.parse(raw);

  if (parsed.keyType !== 'ika-2pc-mpc') {
    throw new Error(`Wallet ${walletId} is not an Ika dWallet (keyType: ${parsed.keyType})`);
  }

  return parsed as IkaWalletFile;
}

export async function unlockShare(walletId: string, passphrase: string): Promise<IkaSharePayload> {
  const wallet = await loadWalletFile(walletId);
  return decryptPayload(wallet.crypto, passphrase);
}

export async function listDWallets(): Promise<IkaDWalletDescriptor[]> {
  const { readdir } = await import('node:fs/promises');
  await ensureVaultDirs();

  const files = await readdir(WALLETS_DIR);
  const wallets: IkaDWalletDescriptor[] = [];

  for (const file of files) {
    if (!file.endsWith('.json')) continue;
    try {
      const raw = await readFile(join(WALLETS_DIR, file), 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed.keyType !== 'ika-2pc-mpc') continue;

      wallets.push({
        owsVersion: 2,
        id: parsed.id,
        name: parsed.name,
        createdAt: parsed.createdAt,
        dwalletId: parsed.dwalletId,
        dwalletCapId: parsed.dwalletCapId,
        curve: parsed.curve,
        kind: parsed.kind,
        accounts: parsed.accounts,
        metadata: parsed.metadata ?? {},
      });
    } catch {
      // skip corrupted wallet files
    }
  }

  return wallets;
}

export async function deleteWallet(walletId: string): Promise<void> {
  const filePath = join(WALLETS_DIR, `${walletId}.json`);
  const { writeFile: wf, unlink } = await import('node:fs/promises');

  // secure overwrite before unlink
  const overwrite = randomBytes(4096);
  await wf(filePath, overwrite);
  await unlink(filePath);
}
