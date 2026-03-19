/**
 * File-backed approval request store
 */

import { randomUUID } from 'crypto';
import { promises as fs } from 'fs';
import path from 'path';
import { ApprovalRequest, ApprovalStatus } from '../types/index.js';

async function ensureStoreExists(storePath: string): Promise<void> {
  await fs.mkdir(path.dirname(storePath), { recursive: true });

  try {
    await fs.access(storePath);
  } catch {
    await fs.writeFile(storePath, '[]', 'utf-8');
  }
}

async function readStore(storePath: string): Promise<ApprovalRequest[]> {
  await ensureStoreExists(storePath);
  const content = await fs.readFile(storePath, 'utf-8');
  const parsed = JSON.parse(content) as ApprovalRequest[];
  return Array.isArray(parsed) ? parsed : [];
}

async function writeStore(storePath: string, requests: ApprovalRequest[]): Promise<void> {
  await ensureStoreExists(storePath);
  await fs.writeFile(storePath, JSON.stringify(requests, null, 2), 'utf-8');
}

export async function createApprovalRequest(
  storePath: string,
  input: Pick<ApprovalRequest, 'toolName' | 'arguments' | 'reason' | 'ruleId'>
): Promise<ApprovalRequest> {
  const requests = await readStore(storePath);
  const request: ApprovalRequest = {
    id: randomUUID(),
    toolName: input.toolName,
    arguments: input.arguments,
    reason: input.reason,
    ruleId: input.ruleId,
    status: 'pending',
    createdAt: new Date().toISOString(),
  };

  requests.push(request);
  await writeStore(storePath, requests);
  return request;
}

export async function listApprovalRequests(
  storePath: string,
  status?: ApprovalStatus
): Promise<ApprovalRequest[]> {
  const requests = await readStore(storePath);
  return status ? requests.filter(request => request.status === status) : requests;
}

export async function getApprovalRequest(
  storePath: string,
  requestId: string
): Promise<ApprovalRequest | undefined> {
  const requests = await readStore(storePath);
  return requests.find(request => request.id === requestId);
}

export async function updateApprovalRequestStatus(
  storePath: string,
  requestId: string,
  status: ApprovalStatus
): Promise<ApprovalRequest> {
  const requests = await readStore(storePath);
  const request = requests.find(entry => entry.id === requestId);

  if (!request) {
    throw new Error(`Approval request not found: ${requestId}`);
  }

  request.status = status;
  request.resolvedAt = new Date().toISOString();
  await writeStore(storePath, requests);
  return request;
}
