/**
 * Audit helper utilities
 */

export function sanitizeAuditArguments(arguments_: Record<string, unknown>): Record<string, unknown> {
  const clone = { ...arguments_ };

  if ('authToken' in clone) {
    clone.authToken = '[REDACTED]';
  }

  return clone;
}
