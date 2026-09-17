import { registryCheckpointMessage } from "@/lib/quantic/registry-commit.mjs";
import { filterRegistryManifestsByHandle, registryFilePath } from "@/lib/quantic/registry-path.mjs";
import { decideRegistryWrite } from "@/lib/quantic/registry-write-core.mjs";
import type { QuanticIdentityManifest } from "@/lib/quantic/manifest-types";

const API_VERSION = "2022-11-28";
const REGISTRY_IDENTITIES_PATH = "registry/identities";

type RegistryConfig = {
  token: string;
  owner: string;
  repo: string;
  branch: string;
};

type GitHubContentResponse = {
  sha?: string;
  content?: string;
  encoding?: string;
};

type GitHubDirectoryEntry = {
  name?: string;
  path?: string;
  type?: string;
};

let lastRegistryError = "";

function config(): RegistryConfig | null {
  const token = process.env.QUANTIC_GITHUB_TOKEN?.trim();
  if (!token) return null;
  return {
    token,
    owner: process.env.QUANTIC_GITHUB_OWNER?.trim() || "XDSawyerLoL",
    repo: process.env.QUANTIC_GITHUB_REPO?.trim() || "QuanticMail",
    branch: process.env.QUANTIC_GITHUB_BRANCH?.trim() || "registry",
  };
}

function headers(current: RegistryConfig) {
  return {
    accept: "application/vnd.github+json",
    authorization: `Bearer ${current.token}`,
    "x-github-api-version": API_VERSION,
    "content-type": "application/json",
  };
}

function contentUrl(current: RegistryConfig, path: string) {
  return `https://api.github.com/repos/${encodeURIComponent(current.owner)}/${encodeURIComponent(current.repo)}/contents/${path}`;
}

function decodeContent(value: string) {
  return Buffer.from(value.replace(/\n/g, ""), "base64").toString("utf8");
}

async function readManifestPath(current: RegistryConfig, path: string) {
  const response = await fetch(`${contentUrl(current, path)}?ref=${encodeURIComponent(current.branch)}`, {
    headers: headers(current),
    cache: "no-store",
  });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`GitHub registry read failed (${response.status}).`);
  const data = (await response.json()) as GitHubContentResponse;
  if (!data.content || data.encoding !== "base64") {
    throw new Error("GitHub registry returned an invalid manifest object.");
  }
  return JSON.parse(decodeContent(data.content)) as QuanticIdentityManifest;
}

async function readRemote(current: RegistryConfig, canonicalAddress: string) {
  const path = registryFilePath(canonicalAddress);
  const manifest = await readManifestPath(current, path);
  if (!manifest) return { path, sha: undefined, manifest: null as QuanticIdentityManifest | null };

  const response = await fetch(`${contentUrl(current, path)}?ref=${encodeURIComponent(current.branch)}`, {
    headers: headers(current),
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`GitHub registry read failed (${response.status}).`);
  const data = (await response.json()) as GitHubContentResponse;
  return { path, sha: data.sha, manifest };
}

export function registryStatus() {
  const current = config();
  return {
    mode: current ? "github" as const : "memory" as const,
    configured: Boolean(current),
    branch: current?.branch ?? null,
    repository: current ? `${current.owner}/${current.repo}` : null,
    degraded: Boolean(lastRegistryError),
    lastError: lastRegistryError || null,
  };
}

export async function loadRegistryManifest(canonicalAddress: string) {
  const current = config();
  if (!current) return null;
  try {
    const result = await readRemote(current, canonicalAddress);
    lastRegistryError = "";
    return result.manifest;
  } catch (error) {
    lastRegistryError = error instanceof Error ? error.message : "GitHub registry unavailable.";
    throw error;
  }
}

export async function loadRegistryManifestsByHandle(locator: string) {
  const current = config();
  if (!current) return [] as QuanticIdentityManifest[];
  try {
    const response = await fetch(`${contentUrl(current, REGISTRY_IDENTITIES_PATH)}?ref=${encodeURIComponent(current.branch)}`, {
      headers: headers(current),
      cache: "no-store",
    });
    if (response.status === 404) return [] as QuanticIdentityManifest[];
    if (!response.ok) throw new Error(`GitHub registry index read failed (${response.status}).`);
    const entries = (await response.json()) as GitHubDirectoryEntry[];
    if (!Array.isArray(entries)) throw new Error("GitHub registry returned an invalid identity index.");

    const paths = entries
      .filter((entry) => entry.type === "file" && typeof entry.path === "string" && entry.path.endsWith(".json"))
      .map((entry) => entry.path as string);
    const settled = await Promise.allSettled(paths.map((path) => readManifestPath(current, path)));
    const manifests = settled
      .filter((item): item is PromiseFulfilledResult<QuanticIdentityManifest | null> => item.status === "fulfilled")
      .map((item) => item.value)
      .filter((manifest): manifest is QuanticIdentityManifest => Boolean(manifest));

    lastRegistryError = "";
    return filterRegistryManifestsByHandle(locator, manifests) as QuanticIdentityManifest[];
  } catch (error) {
    lastRegistryError = error instanceof Error ? error.message : "GitHub registry unavailable.";
    throw error;
  }
}

export async function saveRegistryManifest(manifest: QuanticIdentityManifest) {
  const current = config();
  if (!current) return { persisted: false, mode: "memory" as const };
  try {
    const remote = await readRemote(current, manifest.payload.canonicalAddress);
    const decision = decideRegistryWrite(remote.manifest, manifest);
    if (decision === "unchanged") {
      lastRegistryError = "";
      return { persisted: true, mode: "github" as const, unchanged: true };
    }

    const body: Record<string, unknown> = {
      message: registryCheckpointMessage(remote.path, manifest.payload.sequence),
      content: Buffer.from(JSON.stringify(manifest, null, 2), "utf8").toString("base64"),
      branch: current.branch,
    };
    if (remote.sha) body.sha = remote.sha;

    const response = await fetch(contentUrl(current, remote.path), {
      method: "PUT",
      headers: headers(current),
      body: JSON.stringify(body),
      cache: "no-store",
    });
    if (!response.ok) {
      throw new Error(`GitHub registry write failed (${response.status}).`);
    }
    lastRegistryError = "";
    return { persisted: true, mode: "github" as const, unchanged: false };
  } catch (error) {
    lastRegistryError = error instanceof Error ? error.message : "GitHub registry unavailable.";
    throw error;
  }
}
