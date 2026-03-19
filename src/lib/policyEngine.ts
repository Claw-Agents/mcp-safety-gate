/**
 * Policy Engine for Security Middleware
 * Evaluates tool calls against structured per-tool policy rules
 */

import path from 'path';
import { PolicyDecision, PolicyRule, SafetyGatePolicy } from '../types/index.js';

/**
 * Convert an object to a flat list of all string values (for searching)
 */
function flattenObjectToStrings(obj: unknown): string[] {
  const strings: string[] = [];

  function traverse(current: unknown): void {
    if (typeof current === 'string') {
      strings.push(current);
    } else if (typeof current === 'object' && current !== null) {
      if (Array.isArray(current)) {
        current.forEach(traverse);
      } else {
        Object.values(current).forEach(traverse);
      }
    }
  }

  traverse(obj);
  return strings;
}

function containsKeywords(
  values: string[],
  keywords: string[]
): { matched: boolean; keywords: string[] } {
  const foundKeywords = new Set<string>();

  for (const value of values) {
    const lowerValue = value.toLowerCase();
    for (const keyword of keywords) {
      if (lowerValue.includes(keyword.toLowerCase())) {
        foundKeywords.add(keyword);
      }
    }
  }

  return {
    matched: foundKeywords.size > 0,
    keywords: Array.from(foundKeywords).sort(),
  };
}

function extractPathValue(arguments_: Record<string, unknown>): string | undefined {
  return typeof arguments_.path === 'string' ? arguments_.path : undefined;
}

function matchesPathSubstrings(pathValue: string | undefined, pathSubstrings: string[]): boolean {
  if (!pathValue) {
    return false;
  }

  const normalized = path.normalize(pathValue).toLowerCase();
  return pathSubstrings.some(fragment => normalized.includes(fragment.toLowerCase()));
}

function extractCommandName(arguments_: Record<string, unknown>): string | undefined {
  if (typeof arguments_.command !== 'string') {
    return undefined;
  }

  const command = arguments_.command.trim();
  if (!command) {
    return undefined;
  }

  const [firstToken] = command.split(/\s+/, 1);
  return firstToken?.toLowerCase();
}

function matchesRule(
  toolName: string,
  arguments_: Record<string, unknown>,
  rule: PolicyRule
): { matched: boolean; blockedKeywords?: string[] } {
  if (!rule.tools.includes('*') && !rule.tools.includes(toolName)) {
    return { matched: false };
  }

  const stringValues = flattenObjectToStrings(arguments_);
  const commandName = extractCommandName(arguments_);
  const pathValue = extractPathValue(arguments_);
  const matchers = rule.match;
  let blockedKeywords: string[] | undefined;

  if (matchers.commandNames && matchers.commandNames.length > 0) {
    if (!commandName || !matchers.commandNames.some(name => name.toLowerCase() === commandName)) {
      return { matched: false };
    }
  }

  if (matchers.pathSubstrings && matchers.pathSubstrings.length > 0) {
    if (!matchesPathSubstrings(pathValue, matchers.pathSubstrings)) {
      return { matched: false };
    }
  }

  if (matchers.keywords && matchers.keywords.length > 0) {
    const keywordMatch = containsKeywords(stringValues, matchers.keywords);
    if (!keywordMatch.matched) {
      return { matched: false };
    }
    blockedKeywords = keywordMatch.keywords;
  }

  return {
    matched: true,
    blockedKeywords,
  };
}

/**
 * Evaluate whether a tool call should be allowed, denied, or sent for review.
 */
export function evaluateToolPolicy(
  toolName: string,
  arguments_: Record<string, unknown>,
  policy: SafetyGatePolicy
): PolicyDecision {
  for (const rule of policy.rules) {
    const result = matchesRule(toolName, arguments_, rule);
    if (!result.matched) {
      continue;
    }

    return {
      allowed: rule.effect === 'allow',
      effect: rule.effect,
      reason: `${rule.reason} (rule: ${rule.id})`,
      blockedKeywords: result.blockedKeywords,
      ruleId: rule.id,
    };
  }

  return {
    allowed: true,
    effect: 'allow',
    reason: 'Policy check passed',
  };
}

/**
 * Validate tool arguments against a basic schema
 * (Enhanced validation can use Zod schemas later)
 */
export function validateToolArguments(
  toolName: string,
  arguments_: Record<string, unknown>
): PolicyDecision {
  // Basic sanity checks
  if (typeof arguments_ !== 'object' || arguments_ === null) {
    return {
      allowed: false,
      effect: 'deny',
      reason: 'Invalid arguments: must be an object',
    };
  }

  // Tool-specific validation
  switch (toolName) {
    case 'shell_command':
      if (!('command' in arguments_) || typeof arguments_.command !== 'string') {
        return {
          allowed: false,
          effect: 'deny',
          reason: "Invalid arguments: shell_command requires 'command' string field",
        };
      }
      break;

    case 'write_file':
      if (!('path' in arguments_) || typeof arguments_.path !== 'string') {
        return {
          allowed: false,
          effect: 'deny',
          reason: "Invalid arguments: write_file requires 'path' string field",
        };
      }
      if (!('content' in arguments_) || typeof arguments_.content !== 'string') {
        return {
          allowed: false,
          effect: 'deny',
          reason: "Invalid arguments: write_file requires 'content' string field",
        };
      }
      break;

    case 'read_file':
      if (!('path' in arguments_) || typeof arguments_.path !== 'string') {
        return {
          allowed: false,
          effect: 'deny',
          reason: "Invalid arguments: read_file requires 'path' string field",
        };
      }
      break;
  }

  return {
    allowed: true,
    effect: 'allow',
    reason: 'Arguments validation passed',
  };
}
