/**
 * Policy Engine for Security Middleware
 * Evaluates tool calls against restricted keywords and patterns
 */

import { PolicyDecision } from '../types/index.js';

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

/**
 * Check if a value contains a restricted keyword (case-insensitive substring match)
 */
function containsRestrictedKeyword(
  value: string,
  restrictedKeywords: string[]
): { found: boolean; keywords: string[] } {
  const lowerValue = value.toLowerCase();
  const foundKeywords: string[] = [];

  for (const keyword of restrictedKeywords) {
    if (lowerValue.includes(keyword.toLowerCase())) {
      foundKeywords.push(keyword);
    }
  }

  return {
    found: foundKeywords.length > 0,
    keywords: foundKeywords,
  };
}

/**
 * Evaluate whether a tool call should be blocked
 * Scans all arguments for restricted keywords
 */
export function shouldBlockTool(
  toolName: string,
  arguments_: Record<string, unknown>,
  restrictedKeywords: string[]
): PolicyDecision {
  // Extract all string values from arguments
  const stringValues = flattenObjectToStrings(arguments_);

  // Check each string value against restricted keywords
  const allBlockedKeywords: string[] = [];

  for (const value of stringValues) {
    const { found, keywords } = containsRestrictedKeyword(value, restrictedKeywords);
    if (found) {
      allBlockedKeywords.push(...keywords);
    }
  }

  // Remove duplicates and sort for consistent output
  const uniqueBlockedKeywords = Array.from(new Set(allBlockedKeywords)).sort();

  if (uniqueBlockedKeywords.length > 0) {
    return {
      allowed: false,
      reason: `Blocked: restricted keyword(s) found: ${uniqueBlockedKeywords.join(', ')}`,
      blockedKeywords: uniqueBlockedKeywords,
    };
  }

  return {
    allowed: true,
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
      reason: 'Invalid arguments: must be an object',
    };
  }

  // Tool-specific validation
  switch (toolName) {
    case 'shell_command':
      if (!('command' in arguments_) || typeof arguments_.command !== 'string') {
        return {
          allowed: false,
          reason: "Invalid arguments: shell_command requires 'command' string field",
        };
      }
      break;

    case 'write_file':
      if (!('path' in arguments_) || typeof arguments_.path !== 'string') {
        return {
          allowed: false,
          reason: "Invalid arguments: write_file requires 'path' string field",
        };
      }
      if (!('content' in arguments_) || typeof arguments_.content !== 'string') {
        return {
          allowed: false,
          reason: "Invalid arguments: write_file requires 'content' string field",
        };
      }
      break;

    case 'read_file':
      if (!('path' in arguments_) || typeof arguments_.path !== 'string') {
        return {
          allowed: false,
          reason: "Invalid arguments: read_file requires 'path' string field",
        };
      }
      break;
  }

  return {
    allowed: true,
    reason: 'Arguments validation passed',
  };
}
