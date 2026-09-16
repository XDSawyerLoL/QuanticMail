import { randomUUID } from "node:crypto";
import * as fs from "node:fs/promises";
import { join } from "node:path";

import type { RelayPersistentState } from "../lib/quantic/relay-state.ts";

export type RelayStateStore = {
  load(): Promise<RelayPersistentState | null>;
  save(state: RelayPersistentState): Promise<void>;
};

type RelayFs = Pick<typeof fs, "mkdir" | "open" | "readFile" | "rename" | "rm">;

export function createFileRelayStateStore(
  dataDir: string,
  fsApi: RelayFs = fs,
): RelayStateStore {
  const statePath = join(dataDir, "relay-state.json");

  return {
    async load() {
      let raw: string;
      try {
        raw = await fsApi.readFile(statePath, "utf8");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw error;
      }

      try {
        return JSON.parse(raw) as RelayPersistentState;
      } catch (error) {
        throw new Error(`Impossible de lire ${statePath}: JSON invalide.`, { cause: error });
      }
    },

    async save(state) {
      await fsApi.mkdir(dataDir, { recursive: true, mode: 0o700 });
      const tempPath = join(dataDir, `.relay-state.${process.pid}.${randomUUID()}.tmp`);
      let handle: Awaited<ReturnType<RelayFs["open"]>> | null = null;

      try {
        handle = await fsApi.open(tempPath, "wx", 0o600);
        await handle.writeFile(`${JSON.stringify(state, null, 2)}\n`, "utf8");
        await handle.sync();
        await handle.close();
        handle = null;
        await fsApi.rename(tempPath, statePath);
      } catch (error) {
        if (handle) {
          try {
            await handle.close();
          } catch {
            // Preserve the original storage failure.
          }
        }
        try {
          await fsApi.rm(tempPath, { force: true });
        } catch {
          // Preserve the original storage failure.
        }
        throw error;
      }
    },
  };
}
