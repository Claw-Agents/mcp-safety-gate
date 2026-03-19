#!/usr/bin/env node

// src/index.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// src/lib/config.ts
import path from "path";
import { promises as fs } from "fs";
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
    return {
      version: 1,
      rules: DEFAULT_POLICY_RULES
    };
  }
  const resolvedPolicyPath = path.resolve(policyFilePath);
  const content = await fs.readFile(resolvedPolicyPath, "utf-8");
  const parsed = JSON.parse(content);
  return {
    version: parsed.version ?? 1,
    rules: Array.isArray(parsed.rules) ? parsed.rules : DEFAULT_POLICY_RULES
  };
}
async function loadConfig() {
  const dryRun = process.env.DRY_RUN === "true";
  const verbose = process.env.VERBOSE === "true";
  const auditLogPath = process.env.AUDIT_LOG_PATH || "./audit_log.json";
  const allowedPaths = parseListEnv(process.env.ALLOWED_PATHS, [process.cwd()]).map(
    (entry) => path.resolve(entry)
  );
  const shellAllowedCommands = parseListEnv(
    process.env.SHELL_ALLOWED_COMMANDS,
    DEFAULT_SHELL_ALLOWED_COMMANDS
  ).map((command) => command.toLowerCase());
  const policyFilePath = process.env.POLICY_FILE ? path.resolve(process.env.POLICY_FILE) : void 0;
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
    approvalStorePath: path.resolve(process.env.APPROVAL_STORE_PATH || "./approval-requests.json")
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
  console.log(`  Restricted Keywords: ${config.restrictedKeywords.length} patterns loaded`);
  console.log(`  Verbose Logging: ${config.verbose}`);
}

// src/lib/policyEngine.ts
import path2 from "path";
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
function matchesPathSubstrings(pathValue, pathSubstrings) {
  if (!pathValue) {
    return false;
  }
  const normalized = path2.normalize(pathValue).toLowerCase();
  return pathSubstrings.some((fragment) => normalized.includes(fragment.toLowerCase()));
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
import { promises as fs2 } from "fs";
async function ensureAuditLogExists(auditLogPath) {
  try {
    await fs2.access(auditLogPath);
  } catch {
    await fs2.writeFile(auditLogPath, "", "utf-8");
  }
}
async function logToolCall(entry, auditLogPath, verbose = false) {
  try {
    await ensureAuditLogExists(auditLogPath);
    const jsonLine = JSON.stringify(entry) + "\n";
    await fs2.appendFile(auditLogPath, jsonLine, "utf-8");
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
import { promises as fs3 } from "fs";
import path3 from "path";
async function ensureStoreExists(storePath) {
  await fs3.mkdir(path3.dirname(storePath), { recursive: true });
  try {
    await fs3.access(storePath);
  } catch {
    await fs3.writeFile(storePath, "[]", "utf-8");
  }
}
async function readStore(storePath) {
  await ensureStoreExists(storePath);
  const content = await fs3.readFile(storePath, "utf-8");
  const parsed = JSON.parse(content);
  return Array.isArray(parsed) ? parsed : [];
}
async function writeStore(storePath, requests) {
  await ensureStoreExists(storePath);
  await fs3.writeFile(storePath, JSON.stringify(requests, null, 2), "utf-8");
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
    createdAt: (/* @__PURE__ */ new Date()).toISOString()
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
async function updateApprovalRequestStatus(storePath, requestId, status) {
  const requests = await readStore(storePath);
  const request = requests.find((entry) => entry.id === requestId);
  if (!request) {
    throw new Error(`Approval request not found: ${requestId}`);
  }
  request.status = status;
  request.resolvedAt = (/* @__PURE__ */ new Date()).toISOString();
  await writeStore(storePath, requests);
  return request;
}

// src/lib/toolWrapper.ts
function wrapToolHandler(toolMetadata, originalHandler, config) {
  return async (arguments_) => {
    const startTime = Date.now();
    const toolName = toolMetadata.name;
    const validationDecision = validateToolArguments(toolName, arguments_);
    if (!validationDecision.allowed) {
      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          toolName,
          arguments: arguments_,
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
          arguments: arguments_,
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
      const approvalRequest = await createApprovalRequest(config.approvalStorePath, {
        toolName,
        arguments: arguments_,
        reason: policyDecision.reason,
        ruleId: policyDecision.ruleId
      });
      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          toolName,
          arguments: arguments_,
          decision: "review",
          reason: policyDecision.reason,
          blockedKeywords: policyDecision.blockedKeywords,
          result: "pending",
          executionTimeMs,
          ruleId: policyDecision.ruleId,
          approvalRequestId: approvalRequest.id
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
          arguments: arguments_,
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
          arguments: arguments_,
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
          arguments: arguments_,
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
import { promises as fs5 } from "fs";
import { execFile } from "child_process";
import { promisify } from "util";

// src/lib/fsPolicy.ts
import path4 from "path";
import { promises as fs4 } from "fs";
function isPathWithinAllowedRoots(targetPath, allowedRoots) {
  const resolvedTarget = path4.resolve(targetPath);
  return allowedRoots.some((root) => {
    const resolvedRoot = path4.resolve(root);
    const relative = path4.relative(resolvedRoot, resolvedTarget);
    return relative === "" || !relative.startsWith("..") && !path4.isAbsolute(relative);
  });
}
function assertPathAllowed(targetPath, allowedRoots) {
  const resolvedTarget = path4.resolve(targetPath);
  if (!isPathWithinAllowedRoots(resolvedTarget, allowedRoots)) {
    throw new Error(
      `Path is outside allowed roots: ${resolvedTarget}. Allowed roots: ${allowedRoots.join(", ")}`
    );
  }
  return resolvedTarget;
}
async function ensureParentDirectory(targetPath) {
  await fs4.mkdir(path4.dirname(targetPath), { recursive: true });
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
function assertSafePathTokens(tokens, config) {
  for (const token of tokens) {
    if (token.startsWith("-")) {
      continue;
    }
    const looksLikePath = token.startsWith("/") || token.startsWith("./") || token.startsWith("../") || token.includes("/");
    if (looksLikePath) {
      assertPathAllowed(token, config.allowedPaths);
    }
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
    assertSafePathTokens(args, config);
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
    await fs5.writeFile(resolvedPath, content, "utf-8");
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
    const stats = await fs5.stat(resolvedPath);
    if (stats.size > config.maxFileReadBytes) {
      throw new Error(`File exceeds MAX_FILE_READ_BYTES (${config.maxFileReadBytes} bytes)`);
    }
    const content = await fs5.readFile(resolvedPath, "utf-8");
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
async function dispatchToolExecution(toolName, args, config) {
  switch (toolName) {
    case "shell_command":
      return executeShellCommand(args.command, config);
    case "write_file": {
      const { path: path5, content } = args;
      return writeFileSafely(path5, content, config);
    }
    case "read_file":
      return readFileSafely(args.path, config);
    default:
      return err2(`Unknown tool in approval execution: ${toolName}`);
  }
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
      `Reason: ${item.reason}`,
      `Created: ${item.createdAt}`,
      item.resolvedAt ? `Resolved: ${item.resolvedAt}` : void 0
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
      command: z.string().describe("The shell command to execute")
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
      path: z.string().describe("The file path to write to"),
      content: z.string().describe("The content to write")
    },
    async (args) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: "write_file",
          description: "Write content to a file within configured safe roots"
        },
        async () => {
          const { path: path5, content } = args;
          return writeFileSafely(path5, content, config);
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
      path: z.string().describe("The file path to read from")
    },
    async (args) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: "read_file",
          description: "Read content from a file within configured safe roots"
        },
        async () => {
          const { path: path5 } = args;
          return readFileSafely(path5, config);
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
      status: z.enum(["all", "pending", "approved", "rejected", "executed"]).optional()
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
    "approve_request",
    "Approve a pending review request",
    {
      requestId: z.string().describe("Approval request ID to approve")
    },
    async (args) => {
      try {
        const request = await updateApprovalRequestStatus(
          config.approvalStorePath,
          args.requestId,
          "approved"
        );
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
      requestId: z.string().describe("Approval request ID to reject")
    },
    async (args) => {
      try {
        const request = await updateApprovalRequestStatus(
          config.approvalStorePath,
          args.requestId,
          "rejected"
        );
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
      requestId: z.string().describe("Approval request ID to execute")
    },
    async (args) => {
      try {
        const requestId = args.requestId;
        const request = await getApprovalRequest(config.approvalStorePath, requestId);
        if (!request) {
          return err2(`Approval request not found: ${requestId}`);
        }
        if (request.status !== "approved") {
          return err2(`Approval request ${requestId} is not approved (current status: ${request.status})`);
        }
        const result = await dispatchToolExecution(request.toolName, request.arguments, config);
        await updateApprovalRequestStatus(config.approvalStorePath, requestId, "executed");
        return result;
      } catch (error) {
        return err2(error instanceof Error ? error.message : String(error));
      }
    }
  );
  console.error("[SafetyGate] Registered 7 tools with security wrapping and approvals");
  console.error("[SafetyGate] Starting stdio transport...");
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[SafetyGate] Server running - accepting tool calls on stdio");
}
main().catch((error) => {
  console.error("[SafetyGate] Fatal error:", error);
  process.exit(1);
});
