import { registryFilePath } from "@/lib/quantic/registry-path.mjs";
import type { QuanticIdentityManifest } from "@/lib/quantic/manifest-types";

const API_VERSION = "2022-11-28";

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

async function readRemote(current: RegistryConfig, canonicalAddress: string) {
  const path = registryFilePath(canonicalAddress);
  const response = await fetch(`${contentUrl(current, path)}?ref=${encodeURIComponent(current.branch)}`, {
    headers: headers(current),
    cache: "no-store",
  });
  if (response.status === 404) return { path, sha: undefined, manifest: null as QuanticIdentityManifest | null };
  if (!response.ok) {
    throw new Error(`GitHub registry read failed (${response.status}).`);
  }
  const data = (await response.json()) as GitHubContentResponse;
  if (!data.content || data.encoding !== "base64") {
    throw new Error("GitHub registry returned an invalid manifest object.");
  }
  const manifest = JSON.parse(decodeContent(data.content)) as QuanticIdentityManifest;
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

export async function saveRegistryManifest(manifest: QuanticIdentityManifest) {
  const current = config();
  if (!current) return { persisted: false, mode: "memory" as const };
  try {
    const remote = await readRemote(current, manifest.payload.canonicalAddress);
    if (remote.manifest?.payload?.sequence && remote.manifest.payload.sequence > manifest.payload.sequence) {
      throw new Error("GitHub registry already contains a newer manifest sequence.");
    }
    if (
      remote.manifest?.payload?.sequence === manifest.payload.sequence &&
      JSON.stringify(remote.manifest) === JSON.stringify(manifest)
    ) {
      lastRegistryError = "";
      return { persisted: true, mode: "github" as const, unchanged: true };
    }

    const body: Record<string, unknown> = {
      message: `registry: checkpoint ${manifest.payload.canonicalAddress} #${manifest.payload.sequence}`,
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
