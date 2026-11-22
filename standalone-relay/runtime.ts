import {randomBytes} from "node:crypto";
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

/**
 * A single-process, opt-in SYNTHETIC relay-wide write fence. Saved atomically
 * with the current relay state. Not a distributed fence or production cutover.
 */
export type MigrationLabFence = {
  version:1;phase:"frozen";fenceId:string;relayId:string;frozenAt:string;
};
const hex32=/^[a-f0-9]{32}$/,hex64=/^[a-f0-9]{64}$/;
function parseMigrationLabFence(value:unknown):MigrationLabFence|null{
  if(value===undefined||value===null)return null;
  if(!value||typeof value!=="object"||Array.isArray(value))throw Error("Migration lab fence invalid.");
  const v=value as MigrationLabFence;
  if(Object.keys(v).length!==5||v.version!==1||v.phase!=="frozen"
   ||!hex32.test(v.fenceId)||!hex64.test(v.relayId)
   ||typeof v.frozenAt!=="string"||!Number.isFinite(Date.parse(v.frozenAt)))
     throw Error("Migration lab fence invalid.");
  return structuredClone(v);
}

export class RelayRuntime {
  private tail: Promise<void> = Promise.resolve();
  private initialized = false;
  private migrationLabFence:MigrationLabFence|null=null;

  constructor(
    private readonly store: RelayStateStore,
    private readonly migrationLabEnabled=false,
  ) {}

  async initialize() {
    const loaded = await this.store.load();
    const candidate=(loaded as RelayPersistentState & {migrationLabFence?:unknown}|null)?.migrationLabFence;
    const fence=parseMigrationLabFence(candidate);
    // A frozen lab can NEVER restart as an ordinary production relay: this
    // would discard the write fence and allow an uncontrolled mutation.
    if(fence&&!this.migrationLabEnabled)throw Error("Frozen lab relay cannot restart without its write fence.");
    restoreRelayState(loaded ?? createEmptyRelayState());
    this.migrationLabFence=fence;
    this.initialized = true;
  }

  private ensureInitialized() {
    if (!this.initialized) throw new Error("Quantic Relay runtime non initialisé.");
  }

  isMigrationLabFrozen() {
    this.ensureInitialized();
    return this.migrationLabFence!==null;
  }

  getMigrationLabFence() {
    this.ensureInitialized();
    return this.migrationLabFence ? structuredClone(this.migrationLabFence) : null;
  }

  private saveWithFence(fence:MigrationLabFence|null){
    const state:RelayPersistentState & {migrationLabFence?:MigrationLabFence} = exportRelayState();
    if(fence)state.migrationLabFence=structuredClone(fence);
    return this.store.save(state);
  }

  private queueTransaction<T>(operation:()=>Promise<T>):Promise<T>{
    const transaction=this.tail.then(operation);
    this.tail=transaction.then(()=>undefined,()=>undefined);
    return transaction;
  }

  /** This API has no await point inside the callback, so a freeze commit
   * cannot interleave between reading the two mailbox collections. */
  async readMigrationLab<T>(operation:()=>T):Promise<T>{
    this.ensureInitialized();
    if(!this.migrationLabEnabled)throw Error("Migration snapshot laboratory disabled.");
    await this.tail;
    return operation();
  }

  async read<T>(operation: () => T | Promise<T>): Promise<T> {
    this.ensureInitialized();
    await this.tail;
    // Normal read handlers can prune queues or mutate counters. Disallow
    // these while the entire laboratory relay is frozen.
    if(this.migrationLabFence)throw Error("Migration laboratory write fence is active.");
    return operation();
  }

  mutate<T>(operation: () => T | Promise<T>): Promise<T> {
    this.ensureInitialized();
    return this.queueTransaction(async()=>{
      if(this.migrationLabFence)throw Error("Migration laboratory write fence is active.");
      const before=exportRelayState();
      let result:T|undefined,operationError:unknown;
      try{result=await operation();}catch(error){operationError=error;}
      const after=exportRelayState();
      try{await this.store.save(after);}
      catch(storageError){restoreRelayState(before);throw storageError;}
      if(operationError)throw operationError;
      return result as T;
    });
  }

  /** Serialized after previously accepted mutations, and written to disk
   * before returning the identifier. Restart preserves the fence. */
  freezeMigrationLab(relayId:string):Promise<MigrationLabFence>{
    this.ensureInitialized();
    if(!this.migrationLabEnabled||!hex64.test(relayId))
      throw Error("Migration lab freeze not permitted.");
    return this.queueTransaction(async()=>{
      if(this.migrationLabFence)throw Error("Migration laboratory already frozen.");
      const fence:MigrationLabFence={version:1,phase:"frozen",
        relayId,fenceId:randomBytes(16).toString("hex"),
        frozenAt:new Date().toISOString()};
      await this.saveWithFence(fence);
      this.migrationLabFence=fence;
      return structuredClone(fence);
    });
  }

  /** Laboratory rollback only. Never commits a real account migration. */
  releaseMigrationLab(fenceId:string):Promise<void>{
    this.ensureInitialized();
    if(!this.migrationLabEnabled||!hex32.test(fenceId))
      throw Error("Migration lab release not permitted.");
    return this.queueTransaction(async()=>{
      if(!this.migrationLabFence||this.migrationLabFence.fenceId!==fenceId)
        throw Error("Migration laboratory fence mismatch.");
      await this.saveWithFence(null);
      this.migrationLabFence=null;
    });
  }

  async flush() {
    this.ensureInitialized();
    await this.tail;
    // Do not reserialize / prune the state while a durable freeze is active.
    if(!this.migrationLabFence)await this.saveWithFence(null);
  }
}
