/**
 * Write preview helpers for approval UX
 */

import { promises as fs } from 'fs';
import { isPathWithinAllowedRoots } from './fsPolicy.js';

function trimTrailingEmptyLine(lines: string[]): string[] {
  return lines.length > 0 && lines[lines.length - 1] === '' ? lines.slice(0, -1) : lines;
}

function buildUnifiedDiff(currentContent: string, nextContent: string, maxChangedLines = 80): string {
  const currentLines = trimTrailingEmptyLine(currentContent.split('\n'));
  const nextLines = trimTrailingEmptyLine(nextContent.split('\n'));

  let prefix = 0;
  while (
    prefix < currentLines.length &&
    prefix < nextLines.length &&
    currentLines[prefix] === nextLines[prefix]
  ) {
    prefix += 1;
  }

  let currentSuffix = currentLines.length - 1;
  let nextSuffix = nextLines.length - 1;
  while (
    currentSuffix >= prefix &&
    nextSuffix >= prefix &&
    currentLines[currentSuffix] === nextLines[nextSuffix]
  ) {
    currentSuffix -= 1;
    nextSuffix -= 1;
  }

  const removed = currentLines.slice(prefix, currentSuffix + 1);
  const added = nextLines.slice(prefix, nextSuffix + 1);
  const changedLineCount = removed.length + added.length;

  const diffLines = [
    `@@ -${prefix + 1},${Math.max(removed.length, 0)} +${prefix + 1},${Math.max(added.length, 0)} @@`,
    ...removed.map(line => `-${line}`),
    ...added.map(line => `+${line}`),
  ];

  if (changedLineCount > maxChangedLines) {
    return [
      ...diffLines.slice(0, maxChangedLines + 1),
      `... diff truncated (${changedLineCount - maxChangedLines} more changed lines)`,
    ].join('\n');
  }

  return diffLines.join('\n');
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
    const diff = buildUnifiedDiff(existing, content);

    return [
      `Write preview`,
      `Existing bytes: ${currentBytes}`,
      `Proposed bytes: ${nextBytes}`,
      `--- Unified diff ---`,
      diff,
    ].join('\n');
  } catch {
    const addedLines = trimTrailingEmptyLine(content.split('\n')).map(line => `+${line}`);
    return [
      `Write preview`,
      `New file`,
      `Proposed bytes: ${nextBytes}`,
      `--- Unified diff ---`,
      `@@ -0,0 +1,${addedLines.length} @@`,
      ...addedLines,
    ].join('\n');
  }
}
