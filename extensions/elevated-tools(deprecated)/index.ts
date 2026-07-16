import type { OpenClawExtension } from "@openclaw/sdk";
import * as os from "os";
import * as path from "path";
import * as fs from "fs";

const LOG_DIR = path.join(os.homedir(), ".openclaw", "logs", "elevated-tools");
const CONFIG_PATH = path.join(__dirname, "config.json");

function ensureLogDir() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}

function getLogFile() {
  const d = new Date();
  const name = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}.log`;
  return path.join(LOG_DIR, name);
}

function localLog(level: string, msg: string) {
  try {
    ensureLogDir();
    const ts = new Date().toISOString();
    const line = `[${ts}] [${level}] ${msg}\n`;
    fs.appendFileSync(getLogFile(), line, "utf8");
  } catch {}
}

interface ElevateConfig {
  allowList: string[];
  denyList: string[];
  defaultAction: "deny" | "allow";
}

function loadConfig(): ElevateConfig {
  try {
    const raw = fs.readFileSync(CONFIG_PATH, "utf8");
    return JSON.parse(raw);
  } catch (e) {
    localLog("ERROR", `[elevated-tools] failed to load config.json: ${String(e)}`);
    return { allowList: [], denyList: [], defaultAction: "deny" };
  }
}

const config = loadConfig();

const ALLOW_LIST = config.allowList.map(s => new RegExp(s, "i"));
const DENY_LIST = config.denyList.map(s => new RegExp(s, "i"));
const DEFAULT_ACTION: "deny" | "allow" = config.defaultAction;

async function fetchRules() {
    // todo: fetch rules from remote server
    return { allow: ALLOW_LIST, deny: DENY_LIST };
}

function matchAny(command: string, rules: RegExp[]): RegExp | null {
  for (const r of rules) {
    if (r.test(command)) return r;
  }
  return null;
}

// 决策引擎
async function shouldElevate(api: any, toolName: string, command?: string) {
  if (toolName !== "exec" || !command) return false;

  const { allow, deny } = await fetchRules();

  // DENY 优先
  const denyHit = matchAny(command, deny);
  if (denyHit) {
    const msg = `[elevated-tools] DENY hit: command=${JSON.stringify(command)}`;
    api.logger.warn(msg);
    localLog("WARN", msg);
    return false;
  }

  // ALLOW
  const allowHit = matchAny(command, allow);
  if (allowHit) {
    const msg = `[elevated-tools] ALLOW hit: command=${JSON.stringify(command)}`;
    api.logger.info(msg);
    localLog("INFO", msg);
    return true;
  }

  // 默认行为
  const msg = `[elevated-tools] default ${DEFAULT_ACTION}: command=${JSON.stringify(command)}`;
  api.logger.info(msg);
  localLog("INFO", msg);
  return DEFAULT_ACTION === "allow";
}

// =====================
// 插件
// =====================
const extension: OpenClawExtension = {
  id: "elevated-tools",
  name: "elevated-tools",
  version: "1.0.0",
  description: "allow + deny based elevation control",

  register: (api) => {
    api.logger.info("[elevated-tools] v1.0.0 Initializing...");
    localLog("INFO", "[elevated-tools] v1.0.0 Initializing...");

    api.on("before_tool_call", async (event) => {
      const { toolName } = event;
      const { elevated: _, host: __, ...cleanParams } = event.params || {};

      const command = cleanParams?.command || "";
      localLog("DEBUG", `[elevated-tools] before_tool_call: toolName=${toolName}, command=${JSON.stringify(command)}`);

      const needElevate = await shouldElevate(api, toolName, command);

      return {
        ...event,
        params: {
          ...cleanParams,
          elevated: needElevate
        }
      };
    }, { priority: 8 });

    api.logger.info(`[elevated-tools] registered successfully`);
    localLog("INFO", `[elevated-tools] registered successfully`);
  }
};

export default extension;
