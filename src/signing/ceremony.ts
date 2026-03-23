/**
 * Bridges OWS sign operations to Ika's 2PC-MPC signing ceremony.
 *
 * Two modes:
 *
 * On-chain (trustless): User computes partial sig → submits to policy contract
 * on the policy chain → contract validates tx → contract requests Ika signature
 * atomically. Policy check and sign request cannot be separated.
 *
 * Off-chain (flexible): User computes partial sig → calls Ika SDK directly
 * with raw DWalletCap. OWS local policies still enforced, but no on-chain
 * policy enforcement. Useful for self-custodied wallets or development.
 */

import type { IkaSignRequest, IkaSignResult, IkaSharePayload, SigningMode } from '../types.js';
import { resolveChain } from '../chains/registry.js';
import { unlockShare, loadWalletFile } from '../storage/vault.js';
import { consumePresign } from './presign.js';

export interface IkaClientAdapter {
  computeUserSignMessage(params: {
    publicOutput: Uint8Array;
    userSecretKeyShare: Uint8Array;
    presignData: Uint8Array;
    message: Uint8Array;
    hashScheme: number;
    signatureAlgorithm: number;
    curve: number;
  }): Promise<Uint8Array>;

  getPresignData(presignId: string): Promise<Uint8Array>;

  decryptUserShare(params: {
    decryptionKey: Uint8Array;
    encryptedShareId: string;
    publicOutput: Uint8Array;
    curve: number;
  }): Promise<{ secretShare: Uint8Array }>;

  /**
   * Off-chain mode: approve message + request sign + wait for signature
   * directly via Ika SDK using a raw DWalletCap.
   */
  signOffChain(params: {
    dwalletCapId: string;
    verifiedPresignCapId: string;
    messageUserSignature: Uint8Array;
    message: Uint8Array;
    curve: number;
    signatureAlgorithm: number;
    hashScheme: number;
  }): Promise<{ signature: Uint8Array; signSessionId: string }>;

  /**
   * On-chain mode: submit user contribution to a policy contract on the
   * policy chain. The contract validates the tx against its policies and,
   * if approved, atomically requests Ika's signature.
   */
  signOnChain(params: {
    policyContractId: string;
    dwalletId: string;
    verifiedPresignCapId: string;
    messageUserSignature: Uint8Array;
    message: Uint8Array;
    curve: number;
    signatureAlgorithm: number;
    hashScheme: number;
  }): Promise<{ signature: Uint8Array; signSessionId: string }>;
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
  const mode: SigningMode = request.mode ?? 'on-chain';

  if (wallet.curve !== chain.curve) {
    throw new Error(
      `Wallet curve ${wallet.curve} incompatible with chain ${request.chainId} (expects ${chain.curve})`,
    );
  }

  if (mode === 'on-chain' && !request.policyContractId) {
    throw new Error('On-chain mode requires policyContractId');
  }

  const signatureAlgorithm = request.signatureAlgorithm ?? chain.signatureAlgorithm;
  const hashScheme = request.hashScheme ?? chain.hashScheme;

  // Step 1: Consume a pre-computed presign
  const presign = await consumePresign(request.walletId);
  if (!presign || !presign.verifiedCapId) {
    throw new Error(
      `No verified presigns available for wallet ${request.walletId}. ` +
      `Replenish with requestPresigns().`,
    );
  }

  // Step 2: Decrypt share and compute user contribution
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

  // Step 3: Request Ika signature — on-chain or off-chain
  const sigParams = {
    verifiedPresignCapId: presign.verifiedCapId,
    messageUserSignature,
    message: request.message,
    curve: wallet.curve,
    signatureAlgorithm,
    hashScheme,
  };

  let result: { signature: Uint8Array; signSessionId: string };

  if (mode === 'on-chain') {
    result = await ikaClient.signOnChain({
      ...sigParams,
      policyContractId: request.policyContractId!,
      dwalletId: wallet.dwalletId,
    });
  } else {
    result = await ikaClient.signOffChain({
      ...sigParams,
      dwalletCapId: wallet.dwalletCapId,
    });
  }

  return {
    signature: result.signature,
    signSessionId: result.signSessionId,
    mode,
  };
}
