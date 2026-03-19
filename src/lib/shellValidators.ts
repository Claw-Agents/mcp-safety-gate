/**
 * Per-command shell validators for Safety Gate
 */

import { SafetyGateConfig } from '../types/index.js';
import { assertPathAllowed } from './fsPolicy.js';

function extractPathLikeTokens(tokens: string[]): string[] {
  return tokens.filter(token => {
    if (token.startsWith('-')) {
      return false;
    }

    return (
      token.startsWith('/') ||
      token.startsWith('./') ||
      token.startsWith('../') ||
      token.includes('/') ||
      token.includes('.')
    );
  });
}

function assertPathsAllowed(tokens: string[], config: SafetyGateConfig): void {
  for (const token of extractPathLikeTokens(tokens)) {
    assertPathAllowed(token, config.allowedPaths);
  }
}

function validateLs(args: string[], config: SafetyGateConfig): void {
  assertPathsAllowed(args, config);
}

function validateCatLike(commandName: string, args: string[], config: SafetyGateConfig): void {
  const pathArgs = extractPathLikeTokens(args);

  if (pathArgs.length === 0) {
    throw new Error(`${commandName} requires at least one path argument`);
  }

  assertPathsAllowed(pathArgs, config);
}

function validateFind(args: string[], config: SafetyGateConfig): void {
  const joined = args.join(' ');
  const blockedFragments = ['-exec', '-delete', '-ok', '-okdir'];

  for (const fragment of blockedFragments) {
    if (joined.includes(fragment)) {
      throw new Error(`find argument '${fragment}' is not allowed`);
    }
  }

  const searchRoots = args.filter(arg => !arg.startsWith('-'));
  if (searchRoots.length === 0) {
    throw new Error('find requires an explicit search root');
  }

  assertPathsAllowed([searchRoots[0]], config);
}

function validateGrep(args: string[], config: SafetyGateConfig): void {
  if (args.includes('-R') || args.includes('-r') || args.includes('--recursive')) {
    throw new Error('recursive grep is not allowed');
  }

  const pathArgs = extractPathLikeTokens(args);
  if (pathArgs.length === 0) {
    throw new Error('grep requires an explicit file path');
  }

  assertPathsAllowed(pathArgs, config);
}

function validateEcho(args: string[]): void {
  const totalLength = args.join(' ').length;
  if (totalLength > 4096) {
    throw new Error('echo payload is too large');
  }
}

export function validateShellArguments(
  commandName: string,
  args: string[],
  config: SafetyGateConfig
): void {
  switch (commandName) {
    case 'pwd':
    case 'which':
      return;
    case 'ls':
      return validateLs(args, config);
    case 'cat':
    case 'head':
    case 'tail':
      return validateCatLike(commandName, args, config);
    case 'find':
      return validateFind(args, config);
    case 'grep':
      return validateGrep(args, config);
    case 'echo':
      return validateEcho(args);
    case 'wc':
      return validateCatLike(commandName, args, config);
    default:
      throw new Error(`No validator implemented for allowlisted command '${commandName}'`);
  }
}
