import type { PresignEntry, PresignPool } from '../types.js';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

const PRESIGN_DIR = join(homedir(), '.ows', 'presigns');

export async function loadPresignPool(walletId: string): Promise<PresignPool> {
  await mkdir(PRESIGN_DIR, { recursive: true });
  const filePath = join(PRESIGN_DIR, `${walletId}.json`);
  try {
    const raw = await readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return { walletId, presigns: [] };
  }
}

export async function savePresignPool(pool: PresignPool): Promise<void> {
  await mkdir(PRESIGN_DIR, { recursive: true });
  const filePath = join(PRESIGN_DIR, `${pool.walletId}.json`);
  await writeFile(filePath, JSON.stringify(pool, null, 2), 'utf8');
}

export async function consumePresign(walletId: string): Promise<PresignEntry | null> {
  const pool = await loadPresignPool(walletId);
  const available = pool.presigns.find((p) => p.state === 'verified');

  if (!available) return null;

  available.state = 'consumed';
  await savePresignPool(pool);
  return available;
}

export async function addPresign(walletId: string, entry: PresignEntry): Promise<void> {
  const pool = await loadPresignPool(walletId);
  pool.presigns.push(entry);
  await savePresignPool(pool);
}

export async function getAvailablePresignCount(walletId: string): Promise<number> {
  const pool = await loadPresignPool(walletId);
  return pool.presigns.filter((p) => p.state === 'verified').length;
}
