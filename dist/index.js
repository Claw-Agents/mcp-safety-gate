#!/usr/bin/env node

// src/index.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z as z3 } from "zod";

// src/lib/config.ts
import path2 from "path";
import { promises as fs2 } from "fs";

// src/lib/policySchema.ts
import { z } from "zod";
var ruleEffectSchema = z.enum(["allow", "deny", "review"]);
var policyRuleSchema = z.object({
  id: z.string().min(1, "Rule id is required"),
  effect: ruleEffectSchema,
  reason: z.string().min(1, "Rule reason is required"),
  tools: z.array(z.string().min(1)).min(1, "At least one tool must be listed"),
  match: z.object({
    keywords: z.array(z.string().min(1)).optional(),
    pathSubstrings: z.array(z.string().min(1)).optional(),
    pathRegexes: z.array(z.string().min(1)).optional(),
    pathBasenames: z.array(z.string().min(1)).optional(),
    pathExtensions: z.array(z.string().min(1)).optional(),
    commandNames: z.array(z.string().min(1)).optional(),
    commandArgsRegexes: z.array(z.string().min(1)).optional()
  }).superRefine((value, ctx) => {
    const hasMatcher = (value.keywords?.length ?? 0) > 0 || (value.pathSubstrings?.length ?? 0) > 0 || (value.pathRegexes?.length ?? 0) > 0 || (value.pathBasenames?.length ?? 0) > 0 || (value.pathExtensions?.length ?? 0) > 0 || (value.commandNames?.length ?? 0) > 0 || (value.commandArgsRegexes?.length ?? 0) > 0;
    if (!hasMatcher) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Rule match must contain at least one matcher"
      });
    }
  })
});
var safetyGatePolicySchema = z.object({
  version: z.number().int().positive(),
  rules: z.array(policyRuleSchema)
});
function validatePolicy(input) {
  return safetyGatePolicySchema.parse(input);
}

// src/lib/approverAuth.ts
import { promises as fs } from "fs";
import path from "path";

// src/lib/approverSchema.ts
import { z as z2 } from "zod";
var approverEntrySchema = z2.object({
  id: z2.string().min(1, "Approver id is required"),
  tokenEnv: z2.string().min(1, "Approver tokenEnv is required")
});
var approverAuthSchema = z2.object({
  version: z2.number().int().positive(),
  approvers: z2.array(approverEntrySchema).min(1, "At least one approver must be configured")
});
function validateApproverAuth(input) {
  return approverAuthSchema.parse(input);
}

// src/lib/approverAuth.ts
async function loadApproverAuth(mode, approverAuthFilePath) {
  if (mode === "off") {
    return void 0;
  }
  if (!approverAuthFilePath) {
    throw new Error("APPROVER_AUTH_MODE=token requires APPROVER_AUTH_FILE");
  }
  const resolvedPath = path.resolve(approverAuthFilePath);
  const content = await fs.readFile(resolvedPath, "utf-8");
  const parsed = JSON.parse(content);
  try {
    return validateApproverAuth(parsed);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid approver auth file at ${resolvedPath}: ${message}`);
  }
}
function authenticateApprover(approver, authToken, config) {
  if (config.approverAuthMode === "off") {
    return {
      approver: approver ?? "unverified-approver",
      authenticated: false
    };
  }
  if (!approver) {
    throw new Error("Approver id is required when approver auth is enabled");
  }
  if (!authToken) {
    throw new Error("authToken is required when approver auth is enabled");
  }
  const approverConfig = config.approverAuth?.approvers.find((entry) => entry.id === approver);
  if (!approverConfig) {
    throw new Error(`Unknown approver: ${approver}`);
  }
  const expectedToken = process.env[approverConfig.tokenEnv];
  if (!expectedToken) {
    throw new Error(`Missing environment token for approver '${approver}' (${approverConfig.tokenEnv})`);
  }
  if (authToken !== expectedToken) {
    throw new Error(`Invalid auth token for approver '${approver}'`);
  }
  return {
    approver,
    authenticated: true
  };
}

// src/lib/config.ts
var RESTRICTED_KEYWORDS = [
  // System destructive operations
  "rm",
  "rmdir",
  "del",
  "delete",
  "format",
  "dd",
  "mkfs",
  "shred",
  "wipe",
  // Privilege escalation
  "sudo",
  "su ",
  "chmod 777",
  "chown",
  // Sensitive file paths and patterns
  ".env",
  ".aws/credentials",
  ".ssh/id_rsa",
  "/etc/passwd",
  "secret",
  "token",
  "key",
  "password",
  "apikey",
  "api_key",
  "private_key",
  "github_token",
  "aws_access_key",
  "aws_secret_key",
  // Network dangerous operations
  "wget ",
  "curl ",
  // History/cache clearing
  "clear history",
  "history -c"
];
var DEFAULT_SHELL_ALLOWED_COMMANDS = [
  "pwd",
  "ls",
  "cat",
  "head",
  "tail",
  "wc",
  "find",
  "grep",
  "which",
  "echo"
];
var DEFAULT_POLICY_RULES = [
  {
    id: "deny-dangerous-shell-keywords",
    effect: "deny",
    reason: "Dangerous shell keywords are denied",
    tools: ["shell_command"],
    match: {
      keywords: RESTRICTED_KEYWORDS
    }
  },
  {
    id: "deny-sensitive-write-keywords",
    effect: "deny",
    reason: "Sensitive secrets and credential writes are denied",
    tools: ["write_file"],
    match: {
      keywords: [
        ".env",
        ".aws/credentials",
        ".ssh/id_rsa",
        "private_key",
        "github_token",
        "aws_access_key",
        "aws_secret_key"
      ]
    }
  },
  {
    id: "review-sensitive-read-keywords",
    effect: "review",
    reason: "Sensitive reads require explicit review",
    tools: ["read_file"],
    match: {
      keywords: [".env", ".aws/credentials", ".ssh/id_rsa", "private_key"]
    }
  },
  {
    id: "review-high-impact-project-files",
    effect: "review",
    reason: "Writes to high-impact project files require explicit review",
    tools: ["write_file"],
    match: {
      pathSubstrings: ["package.json", "tsconfig.json", "Dockerfile", ".github/workflows/"]
    }
  }
];
function parseListEnv(value, fallback) {
  if (!value || value.trim().length === 0) {
    return fallback;
  }
  return value.split(",").map((part) => part.trim()).filter(Boolean);
}
function parseNumberEnv(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
async function loadPolicy(policyFilePath) {
  if (!policyFilePath) {
    return validatePolicy({
      version: 1,
      rules: DEFAULT_POLICY_RULES
    });
  }
  const resolvedPolicyPath = path2.resolve(policyFilePath);
  const content = await fs2.readFile(resolvedPolicyPath, "utf-8");
  const parsed = JSON.parse(content);
  try {
    return validatePolicy(parsed);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid policy file at ${resolvedPolicyPath}: ${message}`);
  }
}
async function loadConfig() {
  const dryRun = process.env.DRY_RUN === "true";
  const verbose = process.env.VERBOSE === "true";
  const auditLogPath = process.env.AUDIT_LOG_PATH || "./audit_log.json";
  const allowedPaths = parseListEnv(process.env.ALLOWED_PATHS, [process.cwd()]).map(
    (entry) => path2.resolve(entry)
  );
  const shellAllowedCommands = parseListEnv(
    process.env.SHELL_ALLOWED_COMMANDS,
    DEFAULT_SHELL_ALLOWED_COMMANDS
  ).map((command) => command.toLowerCase());
  const policyFilePath = process.env.POLICY_FILE ? path2.resolve(process.env.POLICY_FILE) : void 0;
  const approverAuthMode = process.env.APPROVER_AUTH_MODE === "token" ? "token" : "off";
  const approverAuthFilePath = process.env.APPROVER_AUTH_FILE ? path2.resolve(process.env.APPROVER_AUTH_FILE) : void 0;
  return {
    dryRun,
    restrictedKeywords: RESTRICTED_KEYWORDS,
    auditLogPath,
    verbose,
    allowedPaths,
    shellAllowedCommands,
    maxFileReadBytes: parseNumberEnv(process.env.MAX_FILE_READ_BYTES, 1024 * 1024),
    maxFileWriteBytes: parseNumberEnv(process.env.MAX_FILE_WRITE_BYTES, 256 * 1024),
    shellCommandTimeoutMs: parseNumberEnv(process.env.SHELL_COMMAND_TIMEOUT_MS, 5e3),
    policy: await loadPolicy(policyFilePath),
    policyFilePath,
    approvalStorePath: path2.resolve(process.env.APPROVAL_STORE_PATH || "./approval-requests.json"),
    approvalTtlSeconds: parseNumberEnv(process.env.APPROVAL_TTL_SECONDS, 3600),
    approverAuthMode,
    approverAuthFilePath,
    approverAuth: await loadApproverAuth(approverAuthMode, approverAuthFilePath)
  };
}
function logConfigOnStartup(config) {
  console.log("[Config] Safety Gate Configuration:");
  console.log(`  Dry-Run Mode: ${config.dryRun}`);
  console.log(`  Audit Log Path: ${config.auditLogPath}`);
  console.log(`  Allowed Paths: ${config.allowedPaths.join(", ")}`);
  console.log(`  Shell Allowed Commands: ${config.shellAllowedCommands.join(", ")}`);
  console.log(`  Max File Read Bytes: ${config.maxFileReadBytes}`);
  console.log(`  Max File Write Bytes: ${config.maxFileWriteBytes}`);
  console.log(`  Shell Command Timeout (ms): ${config.shellCommandTimeoutMs}`);
  console.log(`  Policy File: ${config.policyFilePath ?? "<built-in default>"}`);
  console.log(`  Policy Rules: ${config.policy.rules.length}`);
  console.log(`  Approval Store: ${config.approvalStorePath}`);
  console.log(`  Approval TTL Seconds: ${config.approvalTtlSeconds}`);
  console.log(`  Approver Auth Mode: ${config.approverAuthMode}`);
  console.log(`  Approver Auth File: ${config.approverAuthFilePath ?? "<disabled>"}`);
  console.log(`  Restricted Keywords: ${config.restrictedKeywords.length} patterns loaded`);
  console.log(`  Verbose Logging: ${config.verbose}`);
}

// src/lib/policyEngine.ts
import path3 from "path";
function flattenObjectToStrings(obj) {
  const strings = [];
  function traverse(current) {
    if (typeof current === "string") {
      strings.push(current);
    } else if (typeof current === "object" && current !== null) {
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
function containsKeywords(values, keywords) {
  const foundKeywords = /* @__PURE__ */ new Set();
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
    keywords: Array.from(foundKeywords).sort()
  };
}
function extractPathValue(arguments_) {
  return typeof arguments_.path === "string" ? arguments_.path : void 0;
}
function normalizePathValue(pathValue) {
  return pathValue ? path3.normalize(pathValue).toLowerCase() : void 0;
}
function matchesPathSubstrings(pathValue, pathSubstrings) {
  const normalized = normalizePathValue(pathValue);
  if (!normalized) {
    return false;
  }
  return pathSubstrings.some((fragment) => normalized.includes(fragment.toLowerCase()));
}
function matchesPathRegexes(pathValue, pathRegexes) {
  const normalized = normalizePathValue(pathValue);
  if (!normalized) {
    return false;
  }
  return pathRegexes.some((pattern) => new RegExp(pattern, "i").test(normalized));
}
function matchesPathBasenames(pathValue, basenames) {
  if (!pathValue) {
    return false;
  }
  const basename = path3.basename(pathValue).toLowerCase();
  return basenames.some((entry) => entry.toLowerCase() === basename);
}
function matchesPathExtensions(pathValue, extensions) {
  if (!pathValue) {
    return false;
  }
  const ext = path3.extname(pathValue).toLowerCase();
  return extensions.some((entry) => entry.toLowerCase() === ext);
}
function extractCommandName(arguments_) {
  if (typeof arguments_.command !== "string") {
    return void 0;
  }
  const command = arguments_.command.trim();
  if (!command) {
    return void 0;
  }
  const [firstToken] = command.split(/\s+/, 1);
  return firstToken?.toLowerCase();
}
function extractCommandArgs(arguments_) {
  if (typeof arguments_.command !== "string") {
    return [];
  }
  const command = arguments_.command.trim();
  if (!command) {
    return [];
  }
  const tokens = command.match(/"[^"]*"|'[^']*'|\S+/g) ?? [];
  return tokens.slice(1).map((token) => token.replace(/^['"]|['"]$/g, ""));
}
function matchesCommandArgRegexes(arguments_, regexes) {
  const joinedArgs = extractCommandArgs(arguments_).join(" ");
  if (!joinedArgs) {
    return false;
  }
  return regexes.some((pattern) => new RegExp(pattern, "i").test(joinedArgs));
}
function matchesRule(toolName, arguments_, rule) {
  if (!rule.tools.includes("*") && !rule.tools.includes(toolName)) {
    return { matched: false };
  }
  const stringValues = flattenObjectToStrings(arguments_);
  const commandName = extractCommandName(arguments_);
  const pathValue = extractPathValue(arguments_);
  const matchers = rule.match;
  let blockedKeywords;
  if (matchers.commandNames && matchers.commandNames.length > 0) {
    if (!commandName || !matchers.commandNames.some((name) => name.toLowerCase() === commandName)) {
      return { matched: false };
    }
  }
  if (matchers.commandArgsRegexes && matchers.commandArgsRegexes.length > 0) {
    if (!matchesCommandArgRegexes(arguments_, matchers.commandArgsRegexes)) {
      return { matched: false };
    }
  }
  if (matchers.pathSubstrings && matchers.pathSubstrings.length > 0) {
    if (!matchesPathSubstrings(pathValue, matchers.pathSubstrings)) {
      return { matched: false };
    }
  }
  if (matchers.pathRegexes && matchers.pathRegexes.length > 0) {
    if (!matchesPathRegexes(pathValue, matchers.pathRegexes)) {
      return { matched: false };
    }
  }
  if (matchers.pathBasenames && matchers.pathBasenames.length > 0) {
    if (!matchesPathBasenames(pathValue, matchers.pathBasenames)) {
      return { matched: false };
    }
  }
  if (matchers.pathExtensions && matchers.pathExtensions.length > 0) {
    if (!matchesPathExtensions(pathValue, matchers.pathExtensions)) {
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
    blockedKeywords
  };
}
function evaluateToolPolicy(toolName, arguments_, policy) {
  for (const rule of policy.rules) {
    const result = matchesRule(toolName, arguments_, rule);
    if (!result.matched) {
      continue;
    }
    return {
      allowed: rule.effect === "allow",
      effect: rule.effect,
      reason: `${rule.reason} (rule: ${rule.id})`,
      blockedKeywords: result.blockedKeywords,
      ruleId: rule.id
    };
  }
  return {
    allowed: true,
    effect: "allow",
    reason: "Policy check passed"
  };
}
function validateToolArguments(toolName, arguments_) {
  if (typeof arguments_ !== "object" || arguments_ === null) {
    return {
      allowed: false,
      effect: "deny",
      reason: "Invalid arguments: must be an object"
    };
  }
  switch (toolName) {
    case "shell_command":
      if (!("command" in arguments_) || typeof arguments_.command !== "string") {
        return {
          allowed: false,
          effect: "deny",
          reason: "Invalid arguments: shell_command requires 'command' string field"
        };
      }
      break;
    case "write_file":
      if (!("path" in arguments_) || typeof arguments_.path !== "string") {
        return {
          allowed: false,
          effect: "deny",
          reason: "Invalid arguments: write_file requires 'path' string field"
        };
      }
      if (!("content" in arguments_) || typeof arguments_.content !== "string") {
        return {
          allowed: false,
          effect: "deny",
          reason: "Invalid arguments: write_file requires 'content' string field"
        };
      }
      break;
    case "read_file":
      if (!("path" in arguments_) || typeof arguments_.path !== "string") {
        return {
          allowed: false,
          effect: "deny",
          reason: "Invalid arguments: read_file requires 'path' string field"
        };
      }
      break;
  }
  return {
    allowed: true,
    effect: "allow",
    reason: "Arguments validation passed"
  };
}

// src/lib/auditLogger.ts
import { promises as fs3 } from "fs";
async function ensureAuditLogExists(auditLogPath) {
  try {
    await fs3.access(auditLogPath);
  } catch {
    await fs3.writeFile(auditLogPath, "", "utf-8");
  }
}
async function logToolCall(entry, auditLogPath, verbose = false) {
  try {
    await ensureAuditLogExists(auditLogPath);
    const jsonLine = JSON.stringify(entry) + "\n";
    await fs3.appendFile(auditLogPath, jsonLine, "utf-8");
    if (verbose) {
      console.log(
        `[AuditLog] ${entry.toolName} - ${entry.decision}: ${entry.reason}`
      );
    }
  } catch (error) {
    console.error("[AuditLog] Failed to write audit log:", error);
  }
}

// src/lib/approvalStore.ts
import { randomUUID } from "crypto";
import { promises as fs4 } from "fs";
import path4 from "path";
async function ensureStoreExists(storePath) {
  await fs4.mkdir(path4.dirname(storePath), { recursive: true });
  try {
    await fs4.access(storePath);
  } catch {
    await fs4.writeFile(storePath, "[]", "utf-8");
  }
}
async function readStore(storePath) {
  await ensureStoreExists(storePath);
  const content = await fs4.readFile(storePath, "utf-8");
  const parsed = JSON.parse(content);
  return Array.isArray(parsed) ? parsed : [];
}
async function writeStore(storePath, requests) {
  await ensureStoreExists(storePath);
  await fs4.writeFile(storePath, JSON.stringify(requests, null, 2), "utf-8");
}
async function createApprovalRequest(storePath, input) {
  const requests = await readStore(storePath);
  const request = {
    id: randomUUID(),
    toolName: input.toolName,
    arguments: input.arguments,
    reason: input.reason,
    ruleId: input.ruleId,
    status: "pending",
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    metadata: input.metadata
  };
  requests.push(request);
  await writeStore(storePath, requests);
  return request;
}
async function listApprovalRequests(storePath, status) {
  const requests = await readStore(storePath);
  return status ? requests.filter((request) => request.status === status) : requests;
}
async function getApprovalRequest(storePath, requestId) {
  const requests = await readStore(storePath);
  return requests.find((request) => request.id === requestId);
}
async function updateApprovalRequestStatus(storePath, requestId, status, metadata) {
  const requests = await readStore(storePath);
  const request = requests.find((entry) => entry.id === requestId);
  if (!request) {
    throw new Error(`Approval request not found: ${requestId}`);
  }
  request.status = status;
  request.resolvedAt = (/* @__PURE__ */ new Date()).toISOString();
  request.metadata = {
    ...request.metadata ?? {},
    ...metadata ?? {}
  };
  await writeStore(storePath, requests);
  return request;
}

// src/lib/auditHelpers.ts
function sanitizeAuditArguments(arguments_) {
  const clone = { ...arguments_ };
  if ("authToken" in clone) {
    clone.authToken = "[REDACTED]";
  }
  return clone;
}

// src/lib/writePreview.ts
import { promises as fs6 } from "fs";

// src/lib/fsPolicy.ts
import path5 from "path";
import { promises as fs5 } from "fs";
function isPathWithinAllowedRoots(targetPath, allowedRoots) {
  const resolvedTarget = path5.resolve(targetPath);
  return allowedRoots.some((root) => {
    const resolvedRoot = path5.resolve(root);
    const relative = path5.relative(resolvedRoot, resolvedTarget);
    return relative === "" || !relative.startsWith("..") && !path5.isAbsolute(relative);
  });
}
function assertPathAllowed(targetPath, allowedRoots) {
  const resolvedTarget = path5.resolve(targetPath);
  if (!isPathWithinAllowedRoots(resolvedTarget, allowedRoots)) {
    throw new Error(
      `Path is outside allowed roots: ${resolvedTarget}. Allowed roots: ${allowedRoots.join(", ")}`
    );
  }
  return resolvedTarget;
}
async function ensureParentDirectory(targetPath) {
  await fs5.mkdir(path5.dirname(targetPath), { recursive: true });
}

// src/lib/writePreview.ts
function truncateLines(content, maxLines = 8) {
  return content.split("\n").slice(0, maxLines).join("\n");
}
async function buildWriteFilePreview(targetPath, content, allowedPaths) {
  if (!isPathWithinAllowedRoots(targetPath, allowedPaths)) {
    return void 0;
  }
  const nextBytes = Buffer.byteLength(content, "utf-8");
  try {
    const existing = await fs6.readFile(targetPath, "utf-8");
    const currentBytes = Buffer.byteLength(existing, "utf-8");
    return [
      `Write preview`,
      `Existing bytes: ${currentBytes}`,
      `Proposed bytes: ${nextBytes}`,
      `--- Current (first lines) ---`,
      truncateLines(existing),
      `--- Proposed (first lines) ---`,
      truncateLines(content)
    ].join("\n");
  } catch {
    return [
      `Write preview`,
      `New file`,
      `Proposed bytes: ${nextBytes}`,
      `--- Proposed (first lines) ---`,
      truncateLines(content)
    ].join("\n");
  }
}

// src/lib/toolWrapper.ts
function wrapToolHandler(toolMetadata, originalHandler, config) {
  return async (arguments_) => {
    const startTime = Date.now();
    const toolName = toolMetadata.name;
    const sanitizedArguments = sanitizeAuditArguments(arguments_);
    const validationDecision = validateToolArguments(toolName, arguments_);
    if (!validationDecision.allowed) {
      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          toolName,
          arguments: sanitizedArguments,
          decision: "denied",
          reason: validationDecision.reason,
          result: "error",
          executionTimeMs,
          ruleId: validationDecision.ruleId
        },
        config.auditLogPath,
        config.verbose
      );
      return {
        content: [
          {
            type: "text",
            text: `Validation Error: ${validationDecision.reason}`
          }
        ],
        isError: true
      };
    }
    const policyDecision = evaluateToolPolicy(toolName, arguments_, config.policy);
    if (policyDecision.effect === "deny") {
      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          toolName,
          arguments: sanitizedArguments,
          decision: "denied",
          reason: policyDecision.reason,
          blockedKeywords: policyDecision.blockedKeywords,
          result: "error",
          executionTimeMs,
          ruleId: policyDecision.ruleId
        },
        config.auditLogPath,
        config.verbose
      );
      return {
        content: [
          {
            type: "text",
            text: `Security Policy Violation: ${policyDecision.reason}`
          }
        ],
        isError: true
      };
    }
    if (policyDecision.effect === "review") {
      const preview = toolName === "write_file" && typeof arguments_.path === "string" && typeof arguments_.content === "string" ? await buildWriteFilePreview(arguments_.path, arguments_.content, config.allowedPaths) : void 0;
      const approvalRequest = await createApprovalRequest(config.approvalStorePath, {
        toolName,
        arguments: arguments_,
        reason: policyDecision.reason,
        ruleId: policyDecision.ruleId,
        metadata: preview ? { preview } : void 0
      });
      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          toolName,
          arguments: sanitizedArguments,
          decision: "review",
          reason: policyDecision.reason,
          blockedKeywords: policyDecision.blockedKeywords,
          result: "pending",
          executionTimeMs,
          ruleId: policyDecision.ruleId,
          approvalRequestId: approvalRequest.id,
          lifecycleStage: "review-created"
        },
        config.auditLogPath,
        config.verbose
      );
      return {
        content: [
          {
            type: "text",
            text: `Review Required: ${policyDecision.reason}
Approval Request ID: ${approvalRequest.id}`
          }
        ],
        isError: true
      };
    }
    if (config.dryRun) {
      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          toolName,
          arguments: sanitizedArguments,
          decision: "dryrun",
          reason: "Dry-Run Mode: Tool execution simulated, not actually run",
          result: "success",
          executionTimeMs
        },
        config.auditLogPath,
        config.verbose
      );
      return {
        content: [
          {
            type: "text",
            text: `Dry-Run: Tool '${toolName}' would execute with provided arguments (not actually run)`
          }
        ],
        isError: false
      };
    }
    try {
      const result = await originalHandler();
      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          toolName,
          arguments: sanitizedArguments,
          decision: "allowed",
          reason: "Policy check passed - tool executed",
          result: result.isError ? "error" : "success",
          executionTimeMs
        },
        config.auditLogPath,
        config.verbose
      );
      return result;
    } catch (error) {
      const executionTimeMs = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : String(error);
      await logToolCall(
        {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          toolName,
          arguments: sanitizedArguments,
          decision: "allowed",
          reason: `Tool execution error: ${errorMessage}`,
          result: "error",
          executionTimeMs
        },
        config.auditLogPath,
        config.verbose
      );
      return {
        content: [
          {
            type: "text",
            text: `Tool execution error: ${errorMessage}`
          }
        ],
        isError: true
      };
    }
  };
}

// src/lib/realTools.ts
import { promises as fs7 } from "fs";
import { execFile } from "child_process";
import { promisify } from "util";

// src/lib/shellValidators.ts
function extractPathLikeTokens(tokens) {
  return tokens.filter((token) => {
    if (token.startsWith("-")) {
      return false;
    }
    return token.startsWith("/") || token.startsWith("./") || token.startsWith("../") || token.includes("/") || token.includes(".");
  });
}
function assertPathsAllowed(tokens, config) {
  for (const token of extractPathLikeTokens(tokens)) {
    assertPathAllowed(token, config.allowedPaths);
  }
}
function validateLs(args, config) {
  assertPathsAllowed(args, config);
}
function validateCatLike(commandName, args, config) {
  const pathArgs = extractPathLikeTokens(args);
  if (pathArgs.length === 0) {
    throw new Error(`${commandName} requires at least one path argument`);
  }
  assertPathsAllowed(pathArgs, config);
}
function validateFind(args, config) {
  const joined = args.join(" ");
  const blockedFragments = ["-exec", "-delete", "-ok", "-okdir"];
  for (const fragment of blockedFragments) {
    if (joined.includes(fragment)) {
      throw new Error(`find argument '${fragment}' is not allowed`);
    }
  }
  const searchRoots = args.filter((arg) => !arg.startsWith("-"));
  if (searchRoots.length === 0) {
    throw new Error("find requires an explicit search root");
  }
  assertPathsAllowed([searchRoots[0]], config);
}
function validateGrep(args, config) {
  if (args.includes("-R") || args.includes("-r") || args.includes("--recursive")) {
    throw new Error("recursive grep is not allowed");
  }
  const pathArgs = extractPathLikeTokens(args);
  if (pathArgs.length === 0) {
    throw new Error("grep requires an explicit file path");
  }
  assertPathsAllowed(pathArgs, config);
}
function validateEcho(args) {
  const totalLength = args.join(" ").length;
  if (totalLength > 4096) {
    throw new Error("echo payload is too large");
  }
}
function validateShellArguments(commandName, args, config) {
  switch (commandName) {
    case "pwd":
    case "which":
      return;
    case "ls":
      return validateLs(args, config);
    case "cat":
    case "head":
    case "tail":
      return validateCatLike(commandName, args, config);
    case "find":
      return validateFind(args, config);
    case "grep":
      return validateGrep(args, config);
    case "echo":
      return validateEcho(args);
    case "wc":
      return validateCatLike(commandName, args, config);
    default:
      throw new Error(`No validator implemented for allowlisted command '${commandName}'`);
  }
}

// src/lib/realTools.ts
var execFileAsync = promisify(execFile);
var SHELL_META_PATTERN = /[|&;><`$\\]/;
function ok(text) {
  return {
    content: [{ type: "text", text }],
    isError: false
  };
}
function err(text) {
  return {
    content: [{ type: "text", text }],
    isError: true
  };
}
function tokenizeCommand(command) {
  const trimmed = command.trim();
  if (!trimmed) {
    throw new Error("Command cannot be empty");
  }
  if (SHELL_META_PATTERN.test(trimmed)) {
    throw new Error("Shell metacharacters are not allowed");
  }
  const tokens = trimmed.match(/"[^"]*"|'[^']*'|\S+/g) ?? [];
  return tokens.map((token) => token.replace(/^['"]|['"]$/g, ""));
}
function assertAllowedCommand(commandName, config) {
  if (!config.shellAllowedCommands.includes(commandName.toLowerCase())) {
    throw new Error(
      `Command '${commandName}' is not in the allowed shell command list: ${config.shellAllowedCommands.join(", ")}`
    );
  }
}
async function executeShellCommand(command, config) {
  try {
    const tokens = tokenizeCommand(command);
    const [commandName, ...args] = tokens;
    if (!commandName) {
      throw new Error("Command cannot be empty");
    }
    assertAllowedCommand(commandName, config);
    validateShellArguments(commandName, args, config);
    const { stdout, stderr } = await execFileAsync(commandName, args, {
      cwd: config.allowedPaths[0],
      timeout: config.shellCommandTimeoutMs,
      maxBuffer: config.maxFileReadBytes
    });
    const output = [
      `Command: ${command}`,
      `Exit: 0`,
      stdout ? `STDOUT:
${stdout}` : "STDOUT: <empty>",
      stderr ? `STDERR:
${stderr}` : "STDERR: <empty>"
    ].join("\n");
    return ok(output);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return err(`Shell command rejected or failed: ${message}`);
  }
}
async function writeFileSafely(targetPath, content, config) {
  try {
    const resolvedPath = assertPathAllowed(targetPath, config.allowedPaths);
    const byteLength = Buffer.byteLength(content, "utf-8");
    if (byteLength > config.maxFileWriteBytes) {
      throw new Error(
        `Content exceeds MAX_FILE_WRITE_BYTES (${config.maxFileWriteBytes} bytes)`
      );
    }
    await ensureParentDirectory(resolvedPath);
    await fs7.writeFile(resolvedPath, content, "utf-8");
    return ok(`File written: ${resolvedPath}
Bytes written: ${byteLength}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return err(`Write failed: ${message}`);
  }
}
async function readFileSafely(targetPath, config) {
  try {
    const resolvedPath = assertPathAllowed(targetPath, config.allowedPaths);
    const stats = await fs7.stat(resolvedPath);
    if (stats.size > config.maxFileReadBytes) {
      throw new Error(`File exceeds MAX_FILE_READ_BYTES (${config.maxFileReadBytes} bytes)`);
    }
    const content = await fs7.readFile(resolvedPath, "utf-8");
    return ok(`File read: ${resolvedPath}
Content:
${content}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return err(`Read failed: ${message}`);
  }
}

// src/index.ts
function ok2(text) {
  return {
    content: [{ type: "text", text }],
    isError: false
  };
}
function err2(text) {
  return {
    content: [{ type: "text", text }],
    isError: true
  };
}
async function auditLifecycleEvent(config, toolName, arguments_, options) {
  await logToolCall(
    {
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      toolName,
      arguments: sanitizeAuditArguments(arguments_),
      decision: options.decision,
      reason: options.reason,
      result: options.result,
      approvalRequestId: options.approvalRequestId,
      lifecycleStage: options.lifecycleStage,
      actor: options.actor,
      actorAuthenticated: options.actorAuthenticated
    },
    config.auditLogPath,
    config.verbose
  );
}
async function dispatchToolExecution(toolName, args, config) {
  switch (toolName) {
    case "shell_command":
      return executeShellCommand(args.command, config);
    case "write_file": {
      const { path: path6, content } = args;
      return writeFileSafely(path6, content, config);
    }
    case "read_file":
      return readFileSafely(args.path, config);
    default:
      return err2(`Unknown tool in approval execution: ${toolName}`);
  }
}
function isApprovalExpired(resolvedAt, ttlSeconds) {
  if (!resolvedAt) {
    return false;
  }
  const resolvedMs = new Date(resolvedAt).getTime();
  const nowMs = Date.now();
  return nowMs - resolvedMs > ttlSeconds * 1e3;
}
function summarizeApprovalTarget(item) {
  switch (item.toolName) {
    case "write_file":
    case "read_file":
      return typeof item.arguments.path === "string" ? `path=${item.arguments.path}` : "path=<unknown>";
    case "shell_command":
      return typeof item.arguments.command === "string" ? `command=${item.arguments.command}` : "command=<unknown>";
    default:
      return JSON.stringify(item.arguments);
  }
}
function formatApprovalRequestDetail(item) {
  return [
    `ID: ${item.id}`,
    `Status: ${item.status}`,
    `Tool: ${item.toolName}`,
    `Target: ${summarizeApprovalTarget(item)}`,
    `Reason: ${item.reason}`,
    `Created: ${item.createdAt}`,
    item.resolvedAt ? `Resolved: ${item.resolvedAt}` : void 0,
    item.metadata?.approver ? `Approver: ${item.metadata.approver}` : void 0,
    item.metadata?.authenticated !== void 0 ? `Authenticated: ${item.metadata.authenticated}` : void 0,
    item.metadata?.notes ? `Notes: ${item.metadata.notes}` : void 0,
    item.metadata?.rejectionReason ? `Rejection Reason: ${item.metadata.rejectionReason}` : void 0,
    item.metadata?.preview ? `Preview:
${item.metadata.preview}` : void 0,
    item.metadata?.executor ? `Executor: ${item.metadata.executor}` : void 0,
    item.metadata?.executorAuthenticated !== void 0 ? `Executor Authenticated: ${item.metadata.executorAuthenticated}` : void 0,
    `Arguments: ${JSON.stringify(item.arguments, null, 2)}`
  ].filter(Boolean).join("\n");
}
function formatApprovalRequests(status, items) {
  if (items.length === 0) {
    return `No approval requests found for status: ${status}`;
  }
  return items.map(
    (item) => [
      `ID: ${item.id}`,
      `Status: ${item.status}`,
      `Tool: ${item.toolName}`,
      `Target: ${summarizeApprovalTarget(item)}`,
      `Reason: ${item.reason}`,
      item.metadata?.approver ? `Approver: ${item.metadata.approver}` : void 0,
      item.metadata?.authenticated !== void 0 ? `Authenticated: ${item.metadata.authenticated}` : void 0,
      item.metadata?.executor ? `Executor: ${item.metadata.executor}` : void 0,
      item.metadata?.executorAuthenticated !== void 0 ? `Executor Authenticated: ${item.metadata.executorAuthenticated}` : void 0,
      item.metadata?.notes ? `Notes: ${item.metadata.notes}` : void 0
    ].filter(Boolean).join("\n")
  ).join("\n\n");
}
async function main() {
  const config = await loadConfig();
  console.error("[SafetyGate] Initializing Security Middleware...");
  logConfigOnStartup(config);
  const server = new McpServer({
    name: "Safety Gate",
    version: "1.0.0"
  });
  server.tool(
    "shell_command",
    "Execute an allowlisted shell command within configured safe roots",
    {
      command: z3.string().describe("The shell command to execute")
    },
    async (args) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: "shell_command",
          description: "Execute an allowlisted shell command within configured safe roots"
        },
        async () => executeShellCommand(args.command, config),
        config
      );
      return wrappedHandler(args);
    }
  );
  server.tool(
    "write_file",
    "Write content to a file within configured safe roots",
    {
      path: z3.string().describe("The file path to write to"),
      content: z3.string().describe("The content to write")
    },
    async (args) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: "write_file",
          description: "Write content to a file within configured safe roots"
        },
        async () => {
          const { path: path6, content } = args;
          return writeFileSafely(path6, content, config);
        },
        config
      );
      return wrappedHandler(args);
    }
  );
  server.tool(
    "read_file",
    "Read content from a file within configured safe roots",
    {
      path: z3.string().describe("The file path to read from")
    },
    async (args) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: "read_file",
          description: "Read content from a file within configured safe roots"
        },
        async () => {
          const { path: path6 } = args;
          return readFileSafely(path6, config);
        },
        config
      );
      return wrappedHandler(args);
    }
  );
  server.tool(
    "list_approval_requests",
    "List approval requests tracked by Safety Gate",
    {
      status: z3.enum(["all", "pending", "approved", "rejected", "executed", "expired"]).optional()
    },
    async (args) => {
      const status = args?.status ?? "all";
      const requests = await listApprovalRequests(
        config.approvalStorePath,
        status === "all" ? void 0 : status
      );
      return ok2(formatApprovalRequests(status, requests));
    }
  );
  server.tool(
    "get_approval_request",
    "Get detailed information for a single approval request",
    {
      requestId: z3.string().describe("Approval request ID to inspect")
    },
    async (args) => {
      const requestId = args.requestId;
      const request = await getApprovalRequest(config.approvalStorePath, requestId);
      return request ? ok2(formatApprovalRequestDetail(request)) : err2(`Approval request not found: ${requestId}`);
    }
  );
  server.tool(
    "approve_request",
    "Approve a pending review request",
    {
      requestId: z3.string().describe("Approval request ID to approve"),
      approver: z3.string().optional().describe("Human or system approving the request"),
      authToken: z3.string().optional().describe("Approver authentication token when auth mode is enabled"),
      notes: z3.string().optional().describe("Optional approval notes")
    },
    async (args) => {
      try {
        const typedArgs = args;
        const identity = authenticateApprover(typedArgs.approver, typedArgs.authToken, config);
        const request = await updateApprovalRequestStatus(
          config.approvalStorePath,
          typedArgs.requestId,
          "approved",
          {
            approver: identity.approver,
            authenticated: identity.authenticated,
            notes: typedArgs.notes
          }
        );
        await auditLifecycleEvent(config, "approve_request", typedArgs, {
          decision: "allowed",
          reason: `Approval granted for request ${request.id}`,
          result: "success",
          lifecycleStage: "approved",
          approvalRequestId: request.id,
          actor: identity.approver,
          actorAuthenticated: identity.authenticated
        });
        return ok2(`Approved request ${request.id} for tool ${request.toolName}`);
      } catch (error) {
        return err2(error instanceof Error ? error.message : String(error));
      }
    }
  );
  server.tool(
    "reject_request",
    "Reject a pending review request",
    {
      requestId: z3.string().describe("Approval request ID to reject"),
      approver: z3.string().optional().describe("Human or system rejecting the request"),
      authToken: z3.string().optional().describe("Approver authentication token when auth mode is enabled"),
      rejectionReason: z3.string().optional().describe("Why the request was rejected"),
      notes: z3.string().optional().describe("Optional rejection notes")
    },
    async (args) => {
      try {
        const typedArgs = args;
        const identity = authenticateApprover(typedArgs.approver, typedArgs.authToken, config);
        const request = await updateApprovalRequestStatus(
          config.approvalStorePath,
          typedArgs.requestId,
          "rejected",
          {
            approver: identity.approver,
            authenticated: identity.authenticated,
            rejectionReason: typedArgs.rejectionReason,
            notes: typedArgs.notes
          }
        );
        await auditLifecycleEvent(config, "reject_request", typedArgs, {
          decision: "allowed",
          reason: `Approval rejected for request ${request.id}`,
          result: "success",
          lifecycleStage: "rejected",
          approvalRequestId: request.id,
          actor: identity.approver,
          actorAuthenticated: identity.authenticated
        });
        return ok2(`Rejected request ${request.id} for tool ${request.toolName}`);
      } catch (error) {
        return err2(error instanceof Error ? error.message : String(error));
      }
    }
  );
  server.tool(
    "execute_approved_request",
    "Execute a previously approved request",
    {
      requestId: z3.string().describe("Approval request ID to execute"),
      executor: z3.string().optional().describe("Executor identity for audit trail"),
      authToken: z3.string().optional().describe("Executor authentication token when auth mode is enabled")
    },
    async (args) => {
      try {
        const typedArgs = args;
        const requestId = typedArgs.requestId;
        const request = await getApprovalRequest(config.approvalStorePath, requestId);
        if (!request) {
          return err2(`Approval request not found: ${requestId}`);
        }
        if (request.status !== "approved") {
          await auditLifecycleEvent(config, "execute_approved_request", typedArgs, {
            decision: "denied",
            reason: `Execution blocked because request ${requestId} is in status ${request.status}`,
            result: "error",
            lifecycleStage: request.status === "expired" ? "expired" : "executed",
            approvalRequestId: requestId,
            actor: typedArgs.executor
          });
          return err2(`Approval request ${requestId} is not approved (current status: ${request.status})`);
        }
        const executorIdentity = authenticateApprover(typedArgs.executor, typedArgs.authToken, config);
        if (isApprovalExpired(request.resolvedAt, config.approvalTtlSeconds)) {
          await updateApprovalRequestStatus(config.approvalStorePath, requestId, "expired", {
            approver: request.metadata?.approver,
            authenticated: request.metadata?.authenticated,
            notes: request.metadata?.notes,
            rejectionReason: request.metadata?.rejectionReason,
            executor: executorIdentity.approver,
            executorAuthenticated: executorIdentity.authenticated
          });
          await auditLifecycleEvent(config, "execute_approved_request", typedArgs, {
            decision: "denied",
            reason: `Execution blocked because request ${requestId} expired`,
            result: "error",
            lifecycleStage: "expired",
            approvalRequestId: requestId,
            actor: executorIdentity.approver,
            actorAuthenticated: executorIdentity.authenticated
          });
          return err2(`Approval request ${requestId} has expired`);
        }
        const result = await dispatchToolExecution(request.toolName, request.arguments, config);
        await updateApprovalRequestStatus(config.approvalStorePath, requestId, "executed", {
          approver: request.metadata?.approver,
          authenticated: request.metadata?.authenticated,
          notes: request.metadata?.notes,
          rejectionReason: request.metadata?.rejectionReason,
          executor: executorIdentity.approver,
          executorAuthenticated: executorIdentity.authenticated
        });
        await auditLifecycleEvent(config, "execute_approved_request", typedArgs, {
          decision: result.isError ? "denied" : "allowed",
          reason: result.isError ? `Execution failed for request ${requestId}` : `Execution completed for request ${requestId}`,
          result: result.isError ? "error" : "success",
          lifecycleStage: "executed",
          approvalRequestId: requestId,
          actor: executorIdentity.approver,
          actorAuthenticated: executorIdentity.authenticated
        });
        return result;
      } catch (error) {
        return err2(error instanceof Error ? error.message : String(error));
      }
    }
  );
  console.error("[SafetyGate] Registered 8 tools with security wrapping and approvals");
  console.error("[SafetyGate] Starting stdio transport...");
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[SafetyGate] Server running - accepting tool calls on stdio");
}
main().catch((error) => {
  console.error("[SafetyGate] Fatal error:", error);
  process.exit(1);
});
