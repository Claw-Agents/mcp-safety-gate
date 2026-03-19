/**
 * Write preview helpers for approval UX
 */

import { promises as fs } from 'fs';
import { isPathWithinAllowedRoots } from './fsPolicy.js';

function truncateLines(content: string, maxLines = 8): string {
  return content.split('\n').slice(0, maxLines).join('\n');
}

export async function buildWriteFilePreview(
  targetPath: string,
  content: string,
  allowedPaths: string[]
): Promise<string | undefined> {
  if (!isPathWithinAllowedRoots(targetPath, allowedPaths)) {
    return undefined;
  }

  const nextBytes = Buffer.byteLength(content, 'utf-8');

  try {
    const existing = await fs.readFile(targetPath, 'utf-8');
    const currentBytes = Buffer.byteLength(existing, 'utf-8');

    return [
      `Write preview`,
      `Existing bytes: ${currentBytes}`,
      `Proposed bytes: ${nextBytes}`,
      `--- Current (first lines) ---`,
      truncateLines(existing),
      `--- Proposed (first lines) ---`,
      truncateLines(content),
    ].join('\n');
  } catch {
    return [
      `Write preview`,
      `New file`,
      `Proposed bytes: ${nextBytes}`,
      `--- Proposed (first lines) ---`,
      truncateLines(content),
    ].join('\n');
  }
}
