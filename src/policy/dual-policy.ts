/**
 * Dual policy engine: evaluates both OWS local policies and Ika on-chain policies.
 * Both must allow for a signing request to proceed.
 *
 * Flow:
 * 1. Evaluate OWS declarative rules (fast, in-process)
 * 2. Run OWS executable policy (subprocess, 5s timeout)
 * 3. Check Ika on-chain policy (RPC call to Sui)
 * 4. AND all results — first denial short-circuits
 */

import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { execFile } from 'node:child_process';
import type {
  DualPolicyResult,
  PolicyLayerResult,
  IkaPolicyFile,
  IkaPolicyRule,
  IkaSignRequest,
} from '../types.js';

const POLICIES_DIR = join(homedir(), '.ows', 'policies');

export interface IkaPolicyAdapter {
  checkOnChainPolicy(params: {
    policyId: string;
    dwalletId: string;
    destination?: string;
    message: Uint8Array;
    chainId: string;
  }): Promise<PolicyLayerResult>;
}

interface PolicyContext {
  chainId: string;
  walletId: string;
  message: string;
  timestamp: string;
}

async function loadPolicies(policyIds: string[]): Promise<IkaPolicyFile[]> {
  const policies: IkaPolicyFile[] = [];
  for (const id of policyIds) {
    try {
      const raw = await readFile(join(POLICIES_DIR, `${id}.json`), 'utf8');
      policies.push(JSON.parse(raw));
    } catch {
      // Missing policy file = deny (default-deny principle)
      throw new Error(`Policy file not found: ${id}`);
    }
  }
  return policies;
}

function evaluateDeclarativeRules(
  rules: IkaPolicyRule[],
  request: IkaSignRequest,
): PolicyLayerResult {
  for (const rule of rules) {
    switch (rule.type) {
      case 'allowed_chains': {
        if (rule.chainIds && !rule.chainIds.includes(request.chainId)) {
          return { allowed: false, reason: `Chain ${request.chainId} not in allowed list` };
        }
        break;
      }
      case 'expires_at': {
        if (rule.timestamp && new Date(rule.timestamp) < new Date()) {
          return { allowed: false, reason: `Policy expired at ${rule.timestamp}` };
        }
        break;
      }
      case 'allowed_destinations': {
        // Destination validation requires tx parsing — delegated to executable policy
        break;
      }
      case 'daily_limit': {
        // Spending tracking requires state — delegated to executable policy
        break;
      }
      case 'ika_policy_ref': {
        // Handled in on-chain phase
        break;
      }
    }
  }
  return { allowed: true };
}

async function evaluateExecutablePolicy(
  executablePath: string,
  context: PolicyContext,
): Promise<PolicyLayerResult> {
  return new Promise((resolve) => {
    const child = execFile(executablePath, { timeout: 5000 }, (error, stdout) => {
      if (error) {
        resolve({ allowed: false, reason: `Executable policy error: ${error.message}` });
        return;
      }
      try {
        const result = JSON.parse(stdout);
        resolve({
          allowed: result.allow === true,
          reason: result.reason,
        });
      } catch {
        resolve({ allowed: false, reason: 'Executable policy returned invalid JSON' });
      }
    });

    child.stdin?.write(JSON.stringify(context));
    child.stdin?.end();
  });
}

export async function evaluateOwsPolicies(
  policyIds: string[],
  request: IkaSignRequest,
): Promise<PolicyLayerResult> {
  if (policyIds.length === 0) {
    return { allowed: true };
  }

  const policies = await loadPolicies(policyIds);
  const context: PolicyContext = {
    chainId: request.chainId,
    walletId: request.walletId,
    message: Buffer.from(request.message).toString('hex'),
    timestamp: new Date().toISOString(),
  };

  for (const policy of policies) {
    // Declarative rules first (fast path)
    const ruleResult = evaluateDeclarativeRules(policy.rules, request);
    if (!ruleResult.allowed) {
      return { ...ruleResult, policyId: policy.id };
    }

    // Executable policy (if present)
    if (policy.executable) {
      const execResult = await evaluateExecutablePolicy(policy.executable, context);
      if (!execResult.allowed) {
        return { ...execResult, policyId: policy.id };
      }
    }
  }

  return { allowed: true };
}

export async function evaluateDualPolicy(
  request: IkaSignRequest,
  owsPolicyIds: string[],
  ikaPolicyAdapter: IkaPolicyAdapter | null,
  ikaPolicyId: string | null,
  dwalletId: string,
): Promise<DualPolicyResult> {
  // Layer 1: OWS local policy
  const owsResult = await evaluateOwsPolicies(owsPolicyIds, request);
  if (!owsResult.allowed) {
    return {
      allowed: false,
      owsPolicyResult: owsResult,
      ikaPolicyResult: { allowed: true }, // not evaluated (short-circuit)
    };
  }

  // Layer 2: Ika on-chain policy
  let ikaResult: PolicyLayerResult = { allowed: true };
  if (ikaPolicyAdapter && ikaPolicyId) {
    ikaResult = await ikaPolicyAdapter.checkOnChainPolicy({
      policyId: ikaPolicyId,
      dwalletId,
      message: request.message,
      chainId: request.chainId,
    });
  }

  return {
    allowed: owsResult.allowed && ikaResult.allowed,
    owsPolicyResult: owsResult,
    ikaPolicyResult: ikaResult,
  };
}

export async function listPolicies(): Promise<IkaPolicyFile[]> {
  try {
    const files = await readdir(POLICIES_DIR);
    const policies: IkaPolicyFile[] = [];
    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      const raw = await readFile(join(POLICIES_DIR, file), 'utf8');
      policies.push(JSON.parse(raw));
    }
    return policies;
  } catch {
    return [];
  }
}
