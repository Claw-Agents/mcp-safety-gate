/**
 * Approver auth schema validation for Safety Gate
 */

import { z } from 'zod';
import { ApproverAuthConfig } from '../types/index.js';

const approverEntrySchema = z.object({
  id: z.string().min(1, 'Approver id is required'),
  tokenEnv: z.string().min(1, 'Approver tokenEnv is required'),
});

const approverAuthSchema = z.object({
  version: z.number().int().positive(),
  approvers: z.array(approverEntrySchema).min(1, 'At least one approver must be configured'),
});

export function validateApproverAuth(input: unknown): ApproverAuthConfig {
  return approverAuthSchema.parse(input) as ApproverAuthConfig;
}
