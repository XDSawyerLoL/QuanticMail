import {
  createEmptyRelayState,
  exportRelayState,
  restoreRelayState,
  type RelayPersistentState,
} from "../lib/quantic/relay-state.ts";

export type RelayStateStore = {
  load(): Promise<RelayPersistentState | null>;
  save(state: RelayPersistentState): Promise<void>;
};

export class RelayRuntime {
  private tail: Promise<void> = Promise.resolve();
  private initialized = false;

  constructor(private readonly store: RelayStateStore) {}

  async initialize() {
    const loaded = await this.store.load();
    restoreRelayState(loaded ?? createEmptyRelayState());
    this.initialized = true;
  }

  private ensureInitialized() {
    if (!this.initialized) throw new Error("Quantic Relay runtime non initialisé.");
  }

  async read<T>(operation: () => T | Promise<T>): Promise<T> {
    this.ensureInitialized();
    await this.tail;
    return operation();
  }

  mutate<T>(operation: () => T | Promise<T>): Promise<T> {
    this.ensureInitialized();

    const transaction = this.tail.then(async () => {
      const before = exportRelayState();
      let result: T | undefined;
      let operationError: unknown;

      try {
        result = await operation();
      } catch (error) {
        operationError = error;
      }

      const after = exportRelayState();
      try {
        await this.store.save(after);
      } catch (storageError) {
        restoreRelayState(before);
        throw storageError;
      }

      if (operationError) throw operationError;
      return result as T;
    });

    this.tail = transaction.then(
      () => undefined,
      () => undefined,
    );
    return transaction;
  }

  async flush() {
    this.ensureInitialized();
    await this.tail;
    await this.store.save(exportRelayState());
  }
}
