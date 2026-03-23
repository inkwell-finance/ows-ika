/**
 * MCP (Model Context Protocol) server for AI agent access to Ika dWallets.
 *
 * Exposes OWS-Ika operations as MCP tools that agents can discover and call.
 * All signing requests go through dual policy evaluation before proceeding.
 */

import type { IkaSignRequest, IkaSignResult, IkaDWalletDescriptor, DualPolicyResult } from '../types.js';
import type { IkaClientAdapter } from '../signing/ceremony.js';
import type { IkaPolicyAdapter } from '../policy/dual-policy.js';
import { sign } from '../signing/ceremony.js';
import { listDWallets, loadWalletFile } from '../storage/vault.js';
import { getAvailablePresignCount } from '../signing/presign.js';
import { evaluateDualPolicy } from '../policy/dual-policy.js';

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface McpToolResult {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

export interface OwsIkaMcpServerConfig {
  ikaClient: IkaClientAdapter;
  ikaPolicyAdapter?: IkaPolicyAdapter;
  apiKeyHash?: string;
  policyIds?: string[];
}

export class OwsIkaMcpServer {
  private ikaClient: IkaClientAdapter;
  private ikaPolicyAdapter: IkaPolicyAdapter | null;
  private policyIds: string[];

  constructor(config: OwsIkaMcpServerConfig) {
    this.ikaClient = config.ikaClient;
    this.ikaPolicyAdapter = config.ikaPolicyAdapter ?? null;
    this.policyIds = config.policyIds ?? [];
  }

  getToolDefinitions(): McpToolDefinition[] {
    return [
      {
        name: 'ows_ika_list_wallets',
        description: 'List all Ika dWallets in the local OWS vault',
        inputSchema: { type: 'object', properties: {} },
      },
      {
        name: 'ows_ika_get_wallet',
        description: 'Get details of a specific Ika dWallet including chain accounts and presign availability',
        inputSchema: {
          type: 'object',
          properties: {
            walletId: { type: 'string', description: 'OWS wallet UUID' },
          },
          required: ['walletId'],
        },
      },
      {
        name: 'ows_ika_sign',
        description: 'Sign a message using Ika 2PC-MPC threshold signing. Requires a verified presign.',
        inputSchema: {
          type: 'object',
          properties: {
            walletId: { type: 'string', description: 'OWS wallet UUID' },
            chainId: { type: 'string', description: 'CAIP-2 chain identifier or alias (e.g., "ethereum", "solana", "eip155:8453")' },
            messageHex: { type: 'string', description: 'Hex-encoded message bytes to sign' },
            passphrase: { type: 'string', description: 'Vault passphrase to decrypt the user share' },
          },
          required: ['walletId', 'chainId', 'messageHex', 'passphrase'],
        },
      },
      {
        name: 'ows_ika_check_policy',
        description: 'Dry-run policy evaluation without signing. Returns what both OWS and Ika policies would decide.',
        inputSchema: {
          type: 'object',
          properties: {
            walletId: { type: 'string', description: 'OWS wallet UUID' },
            chainId: { type: 'string', description: 'CAIP-2 chain identifier' },
            messageHex: { type: 'string', description: 'Hex-encoded message bytes' },
          },
          required: ['walletId', 'chainId', 'messageHex'],
        },
      },
      {
        name: 'ows_ika_presign_status',
        description: 'Check available presigns for a wallet',
        inputSchema: {
          type: 'object',
          properties: {
            walletId: { type: 'string', description: 'OWS wallet UUID' },
          },
          required: ['walletId'],
        },
      },
    ];
  }

  async handleToolCall(name: string, args: Record<string, unknown>): Promise<McpToolResult> {
    try {
      switch (name) {
        case 'ows_ika_list_wallets':
          return await this.handleListWallets();
        case 'ows_ika_get_wallet':
          return await this.handleGetWallet(args.walletId as string);
        case 'ows_ika_sign':
          return await this.handleSign(args);
        case 'ows_ika_check_policy':
          return await this.handleCheckPolicy(args);
        case 'ows_ika_presign_status':
          return await this.handlePresignStatus(args.walletId as string);
        default:
          return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { content: [{ type: 'text', text: message }], isError: true };
    }
  }

  private async handleListWallets(): Promise<McpToolResult> {
    const wallets = await listDWallets();
    const summary = await Promise.all(
      wallets.map(async (w) => ({
        id: w.id,
        name: w.name,
        dwalletId: w.dwalletId,
        curve: w.curve,
        kind: w.kind,
        accounts: w.accounts,
        availablePresigns: await getAvailablePresignCount(w.id),
      })),
    );
    return { content: [{ type: 'text', text: JSON.stringify(summary, null, 2) }] };
  }

  private async handleGetWallet(walletId: string): Promise<McpToolResult> {
    const wallet = await loadWalletFile(walletId);
    const presignCount = await getAvailablePresignCount(walletId);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          id: wallet.id,
          name: wallet.name,
          dwalletId: wallet.dwalletId,
          dwalletCapId: wallet.dwalletCapId,
          curve: wallet.curve,
          kind: wallet.kind,
          accounts: wallet.accounts,
          availablePresigns: presignCount,
          metadata: wallet.metadata,
        }, null, 2),
      }],
    };
  }

  private async handleSign(args: Record<string, unknown>): Promise<McpToolResult> {
    const request: IkaSignRequest = {
      walletId: args.walletId as string,
      chainId: args.chainId as string,
      message: Buffer.from(args.messageHex as string, 'hex'),
    };

    // Policy check first (before touching keys)
    const wallet = await loadWalletFile(request.walletId);
    const policyResult = await evaluateDualPolicy(
      request,
      this.policyIds,
      this.ikaPolicyAdapter,
      wallet.metadata.ikaPolicyId as string | null ?? null,
      wallet.dwalletId,
    );

    if (!policyResult.allowed) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            error: 'POLICY_DENIED',
            owsPolicy: policyResult.owsPolicyResult,
            ikaPolicy: policyResult.ikaPolicyResult,
          }, null, 2),
        }],
        isError: true,
      };
    }

    const result = await sign(request, {
      passphrase: args.passphrase as string,
      ikaClient: this.ikaClient,
    });

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          signature: Buffer.from(result.signature).toString('hex'),
          signSessionId: result.signSessionId,
          recoveryId: result.recoveryId,
        }, null, 2),
      }],
    };
  }

  private async handleCheckPolicy(args: Record<string, unknown>): Promise<McpToolResult> {
    const request: IkaSignRequest = {
      walletId: args.walletId as string,
      chainId: args.chainId as string,
      message: Buffer.from(args.messageHex as string, 'hex'),
    };

    const wallet = await loadWalletFile(request.walletId);
    const result = await evaluateDualPolicy(
      request,
      this.policyIds,
      this.ikaPolicyAdapter,
      wallet.metadata.ikaPolicyId as string | null ?? null,
      wallet.dwalletId,
    );

    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  }

  private async handlePresignStatus(walletId: string): Promise<McpToolResult> {
    const count = await getAvailablePresignCount(walletId);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({ walletId, availablePresigns: count }, null, 2),
      }],
    };
  }
}

