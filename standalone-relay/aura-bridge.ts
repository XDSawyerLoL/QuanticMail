const DEFAULT_AURA_URL =
  process.env.AURA_CLOUD_URL?.replace(/\/$/, "") ||
  "https://antiquewhite-dolphin-780448.hostingersite.com";

const TOKEN = process.env.AURA_CLOUD_TOKEN?.trim() ?? "";
const BRIDGE_VERSION = "aura-universal-bridge-v1";

type Json = Record<string, unknown>;

async function post(path: string, body: Json): Promise<Json | null> {
  if (!TOKEN) return null;
  const response = await fetch(DEFAULT_AURA_URL + path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
      authorization: `Bearer ${TOKEN}`,
      "user-agent": "QuanticMail/AURA-Bridge-1",
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(8_000),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`AURA HTTP ${response.status}: ${text.slice(0, 300)}`);
  }
  return text ? JSON.parse(text) as Json : {};
}

export class QuanticMailAuraBridge {
  private heartbeat: NodeJS.Timeout | null = null;

  get enabled() {
    return Boolean(TOKEN);
  }

  async register(publicEndpoint = "") {
    if (!this.enabled) return false;
    try {
      await post("/api/aura/products/register", {
        id: "quantic-mail",
        name: "Quantic Mail",
        objective: "Communication privée, réseau Quantic et messagerie chiffrée.",
        repository: "XDSawyerLoL/QuanticMail",
        endpoint: publicEndpoint,
        criticality: 0.9,
        state: "online",
        capabilities: ["mail", "private-messaging", "identity", "devices", "relay"],
        writable_by_aura: true,
        modification_policy: "branch-test-canary-promote",
        bridge_version: BRIDGE_VERSION,
        runtime: {
          transport: "quantic-relay",
          content_exposure: "none-by-default",
        },
      });
      return true;
    } catch {
      return false;
    }
  }

  async observe(
    state = "online",
    detail = "",
    metadata: Json = {},
  ) {
    if (!this.enabled) return false;
    try {
      await post("/api/aura/products/quantic-mail/observe", {
        state,
        detail,
        metadata: {
          ...metadata,
          privacy: "message-content-not-forwarded",
          bridge_version: BRIDGE_VERSION,
        },
      });
      return true;
    } catch {
      return false;
    }
  }

  async event(type: string, payload: Json = {}) {
    if (!this.enabled) return false;
    try {
      await post("/api/aura/products/quantic-mail/event", {
        type,
        payload: {
          ...payload,
          content_policy: "operational-metadata-only",
        },
      });
      return true;
    } catch {
      return false;
    }
  }

  startHeartbeat(publicEndpoint = "") {
    if (!this.enabled || this.heartbeat) return;
    void this.register(publicEndpoint);
    this.heartbeat = setInterval(() => {
      void this.observe("online", "Quantic Relay actif.", {
        public_endpoint: publicEndpoint,
      });
    }, 300_000);
    this.heartbeat.unref?.();
  }

  stop() {
    if (this.heartbeat) clearInterval(this.heartbeat);
    this.heartbeat = null;
  }
}

export const quanticMailAuraBridge = new QuanticMailAuraBridge();
