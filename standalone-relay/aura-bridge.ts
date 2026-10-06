const DEFAULT_AURA_URL =
  process.env.AURA_CLOUD_URL?.replace(/\/$/, "") ||
  "https://antiquewhite-dolphin-780448.hostingersite.com";

const LEGACY_ALLOWED = ["1", "true", "yes", "oui", "on"].includes(
  String(process.env.AURA_ALLOW_LEGACY_PRODUCT_ADMIN_TOKEN ?? "").trim().toLowerCase(),
);
const LEGACY_TOKEN = LEGACY_ALLOWED
  ? process.env.AURA_CLOUD_TOKEN?.trim() ?? ""
  : "";
const PRODUCT_TOKENS: Record<string, string> = {
  "quantic-mail": (
    process.env.AURA_QUANTIC_MAIL_TOKEN
    ?? process.env.AURA_PRODUCT_TOKEN_QUANTIC_MAIL
    ?? ""
  ).trim(),
  "identity-vault": (
    process.env.AURA_IDENTITY_VAULT_TOKEN
    ?? process.env.AURA_PRODUCT_TOKEN_IDENTITY_VAULT
    ?? ""
  ).trim(),
};
const tokenFor = (productId: string) => PRODUCT_TOKENS[productId] || LEGACY_TOKEN;
const BRIDGE_VERSION = "aura-universal-bridge-v2-scoped";

type Json = Record<string, unknown>;

async function post(productId: string, path: string, body: Json): Promise<Json | null> {
  const token = tokenFor(productId);
  if (!token) return null;
  const response = await fetch(DEFAULT_AURA_URL + path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
      authorization: `Bearer ${token}`,
      "user-agent": "QuanticMail/AURA-Bridge-2",
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
    return Boolean(tokenFor("quantic-mail") || tokenFor("identity-vault"));
  }

  async register(publicEndpoint = "") {
    if (!this.enabled) return false;
    let ok = true;

    if (tokenFor("quantic-mail")) {
      try {
        await post("quantic-mail", "/api/aura/products/register", {
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
      } catch {
        ok = false;
      }
    }

    if (tokenFor("identity-vault")) {
      try {
        await post("identity-vault", "/api/aura/products/register", {
          id: "identity-vault",
          name: "Identity Vault",
          objective: "Coffre d’identité Quantic : identité persistante, récupération chiffrée et portabilité.",
          repository: "XDSawyerLoL/QuanticMail",
          endpoint: publicEndpoint,
          criticality: 0.93,
          state: "online",
          capabilities: ["identity", "vault", "recovery", "portable-identity", "device-trust", "encryption"],
          writable_by_aura: true,
          modification_policy: "branch-test-canary-promote",
          bridge_version: BRIDGE_VERSION,
          runtime: {
            transport: "client-side-vault",
            secret_material_forwarded: false,
            content_exposure: "operational-metadata-only",
          },
        });
      } catch {
        ok = false;
      }
    }
    return ok;
  }

  async observe(
    state = "online",
    detail = "",
    metadata: Json = {},
  ) {
    if (!tokenFor("quantic-mail")) return false;
    try {
      await post("quantic-mail", "/api/aura/products/quantic-mail/observe", {
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

  async observeVault(
    state = "online",
    detail = "Identity Vault disponible via Quantic Mail.",
    metadata: Json = {},
  ) {
    if (!tokenFor("identity-vault")) return false;
    try {
      await post("identity-vault", "/api/aura/products/identity-vault/observe", {
        state,
        detail,
        metadata: {
          ...metadata,
          privacy: "identity-secrets-not-forwarded",
          bridge_version: BRIDGE_VERSION,
        },
      });
      return true;
    } catch {
      return false;
    }
  }

  async event(type: string, payload: Json = {}) {
    if (!tokenFor("quantic-mail")) return false;
    try {
      await post("quantic-mail", "/api/aura/products/quantic-mail/event", {
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
      void this.observeVault("online", "Identity Vault disponible.", {
        public_endpoint: publicEndpoint,
        vault_scope: "client-side-encrypted",
      });
    }, 120_000);
    this.heartbeat.unref?.();
  }

  stop() {
    if (this.heartbeat) clearInterval(this.heartbeat);
    this.heartbeat = null;
  }
}

export const quanticMailAuraBridge = new QuanticMailAuraBridge();
