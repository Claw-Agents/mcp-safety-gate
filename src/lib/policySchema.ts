/**
 * Policy schema validation for Safety Gate
 */

import { z } from 'zod';
import { SafetyGatePolicy } from '../types/index.js';

const ruleEffectSchema = z.enum(['allow', 'deny', 'review']);

const policyRuleSchema = z.object({
  id: z.string().min(1, 'Rule id is required'),
  effect: ruleEffectSchema,
  reason: z.string().min(1, 'Rule reason is required'),
  tools: z.array(z.string().min(1)).min(1, 'At least one tool must be listed'),
  match: z
    .object({
      keywords: z.array(z.string().min(1)).optional(),
      pathSubstrings: z.array(z.string().min(1)).optional(),
      pathRegexes: z.array(z.string().min(1)).optional(),
      pathBasenames: z.array(z.string().min(1)).optional(),
      pathExtensions: z.array(z.string().min(1)).optional(),
      commandNames: z.array(z.string().min(1)).optional(),
      commandArgsRegexes: z.array(z.string().min(1)).optional(),
    })
    .superRefine((value, ctx) => {
      const hasMatcher =
        (value.keywords?.length ?? 0) > 0 ||
        (value.pathSubstrings?.length ?? 0) > 0 ||
        (value.pathRegexes?.length ?? 0) > 0 ||
        (value.pathBasenames?.length ?? 0) > 0 ||
        (value.pathExtensions?.length ?? 0) > 0 ||
        (value.commandNames?.length ?? 0) > 0 ||
        (value.commandArgsRegexes?.length ?? 0) > 0;

      if (!hasMatcher) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'Rule match must contain at least one matcher',
        });
      }
    }),
});

const safetyGatePolicySchema = z.object({
  version: z.number().int().positive(),
  rules: z.array(policyRuleSchema),
});

export function validatePolicy(input: unknown): SafetyGatePolicy {
  return safetyGatePolicySchema.parse(input) as SafetyGatePolicy;
}
