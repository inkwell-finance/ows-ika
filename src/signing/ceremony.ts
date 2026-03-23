/**
 * Bridges OWS sign operations to Ika's 2PC-MPC signing ceremony.
 *
 * The ceremony has 5 phases:
 * 1. Presign (done ahead of time, managed by presign pool)
 * 2. Approve message (on-chain: proves the dWallet owner authorized this message)
 * 3. Compute user contribution (off-chain: decrypts share, computes partial signature)
 * 4. Request sign (on-chain: submits user contribution + message approval)
 * 5. Poll for signature (on-chain: Ika network completes threshold signature)
 */

import type { IkaSignRequest, IkaSignResult, IkaSharePayload } from '../types.js';
import { resolveChain } from '../chains/registry.js';
import { unlockShare, loadWalletFile } from '../storage/vault.js';
import { consumePresign } from './presign.js';

export interface IkaClientAdapter {
  approveMessage(params: {
    dwalletCapId: string;
    curve: number;
    signatureAlgorithm: number;
    hashScheme: number;
    message: Uint8Array;
  }): Promise<{ messageApprovalId: string }>;

  computeUserSignMessage(params: {
    publicOutput: Uint8Array;
    userSecretKeyShare: Uint8Array;
    presignData: Uint8Array;
    message: Uint8Array;
    hashScheme: number;
    signatureAlgorithm: number;
    curve: number;
  }): Promise<Uint8Array>;

  requestSign(params: {
    verifiedPresignCapId: string;
    messageApprovalId: string;
    messageUserSignature: Uint8Array;
  }): Promise<{ signSessionId: string }>;

  waitForSignature(params: {
    signSessionId: string;
    curve: number;
    signatureAlgorithm: number;
  }): Promise<{ signature: Uint8Array }>;

  getPresignData(presignId: string): Promise<Uint8Array>;

  decryptUserShare(params: {
    decryptionKey: Uint8Array;
    encryptedShareId: string;
    publicOutput: Uint8Array;
    curve: number;
  }): Promise<{ secretShare: Uint8Array }>;
}

export interface SignOptions {
  passphrase: string;
  ikaClient: IkaClientAdapter;
}

export async function sign(
  request: IkaSignRequest,
  options: SignOptions,
): Promise<IkaSignResult> {
  const { passphrase, ikaClient } = options;
  const chain = resolveChain(request.chainId);
  const wallet = await loadWalletFile(request.walletId);

  if (wallet.curve !== chain.curve) {
    throw new Error(
      `Wallet curve ${wallet.curve} incompatible with chain ${request.chainId} (expects ${chain.curve})`,
    );
  }

  const signatureAlgorithm = request.signatureAlgorithm ?? chain.signatureAlgorithm;
  const hashScheme = request.hashScheme ?? chain.hashScheme;

  // Phase 1: Consume a pre-computed presign
  const presign = await consumePresign(request.walletId);
  if (!presign || !presign.verifiedCapId) {
    throw new Error(
      `No verified presigns available for wallet ${request.walletId}. ` +
      `Replenish with requestPresigns().`,
    );
  }

  // Phase 2: Approve message on-chain
  const { messageApprovalId } = await ikaClient.approveMessage({
    dwalletCapId: wallet.dwalletCapId,
    curve: wallet.curve,
    signatureAlgorithm,
    hashScheme,
    message: request.message,
  });

  // Phase 3: Decrypt share and compute user contribution
  const sharePayload: IkaSharePayload = await unlockShare(request.walletId, passphrase);
  let secretShare: Uint8Array;

  try {
    const decrypted = await ikaClient.decryptUserShare({
      decryptionKey: sharePayload.decryptionKey,
      encryptedShareId: sharePayload.encryptedShareId,
      publicOutput: sharePayload.publicOutput,
      curve: wallet.curve,
    });
    secretShare = decrypted.secretShare;
  } finally {
    sharePayload.decryptionKey.fill(0);
    sharePayload.encryptionKey.fill(0);
  }

  const presignData = await ikaClient.getPresignData(presign.presignId);

  let messageUserSignature: Uint8Array;
  try {
    messageUserSignature = await ikaClient.computeUserSignMessage({
      publicOutput: sharePayload.publicOutput,
      userSecretKeyShare: secretShare,
      presignData,
      message: request.message,
      hashScheme,
      signatureAlgorithm,
      curve: wallet.curve,
    });
  } finally {
    secretShare.fill(0);
  }

  // Phase 4: Submit to Ika network
  const { signSessionId } = await ikaClient.requestSign({
    verifiedPresignCapId: presign.verifiedCapId,
    messageApprovalId,
    messageUserSignature,
  });

  // Phase 5: Wait for threshold signature
  const { signature } = await ikaClient.waitForSignature({
    signSessionId,
    curve: wallet.curve,
    signatureAlgorithm,
  });

  return {
    signature,
    signSessionId,
  };
}
