/**
 * Filesystem policy helpers for Safety Gate
 */

import path from 'path';
import { promises as fs } from 'fs';

export function isPathWithinAllowedRoots(targetPath: string, allowedRoots: string[]): boolean {
  const resolvedTarget = path.resolve(targetPath);

  return allowedRoots.some(root => {
    const resolvedRoot = path.resolve(root);
    const relative = path.relative(resolvedRoot, resolvedTarget);
    return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
  });
}

export function assertPathAllowed(targetPath: string, allowedRoots: string[]): string {
  const resolvedTarget = path.resolve(targetPath);

  if (!isPathWithinAllowedRoots(resolvedTarget, allowedRoots)) {
    throw new Error(
      `Path is outside allowed roots: ${resolvedTarget}. Allowed roots: ${allowedRoots.join(', ')}`
    );
  }

  return resolvedTarget;
}

export async function ensureParentDirectory(targetPath: string): Promise<void> {
  await fs.mkdir(path.dirname(targetPath), { recursive: true });
}
