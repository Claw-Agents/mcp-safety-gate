/**
 * Approver authentication helpers
 */

import { promises as fs } from 'fs';
import path from 'path';
import { SafetyGateConfig } from '../types/index.js';
import { validateApproverAuth } from './approverSchema.js';

export async function loadApproverAuth(
  mode: SafetyGateConfig['approverAuthMode'],
  approverAuthFilePath?: string
): Promise<SafetyGateConfig['approverAuth']> {
  if (mode === 'off') {
    return undefined;
  }

  if (!approverAuthFilePath) {
    throw new Error('APPROVER_AUTH_MODE=token requires APPROVER_AUTH_FILE');
  }

  const resolvedPath = path.resolve(approverAuthFilePath);
  const content = await fs.readFile(resolvedPath, 'utf-8');
  const parsed = JSON.parse(content);

  try {
    return validateApproverAuth(parsed);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid approver auth file at ${resolvedPath}: ${message}`);
  }
}

export function authenticateApprover(
  approver: string | undefined,
  authToken: string | undefined,
  config: SafetyGateConfig
): { approver: string; authenticated: boolean } {
  if (config.approverAuthMode === 'off') {
    return {
      approver: approver ?? 'unverified-approver',
      authenticated: false,
    };
  }

  if (!approver) {
    throw new Error('Approver id is required when approver auth is enabled');
  }

  if (!authToken) {
    throw new Error('authToken is required when approver auth is enabled');
  }

  const approverConfig = config.approverAuth?.approvers.find(entry => entry.id === approver);
  if (!approverConfig) {
    throw new Error(`Unknown approver: ${approver}`);
  }

  const expectedToken = process.env[approverConfig.tokenEnv];
  if (!expectedToken) {
    throw new Error(`Missing environment token for approver '${approver}' (${approverConfig.tokenEnv})`);
  }

  if (authToken !== expectedToken) {
    throw new Error(`Invalid auth token for approver '${approver}'`);
  }

  return {
    approver,
    authenticated: true,
  };
}
