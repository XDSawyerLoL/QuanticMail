import type { LocalIdentity } from "@/lib/quantic/local-db";

export declare function decideQuanticIdMailboxAccess(
  mailIdentity: LocalIdentity | null | undefined,
  keyId: string | null | undefined,
):
  | { kind: "invalid" }
  | { kind: "mailbox-absent" }
  | { kind: "unbound"; address?: string }
  | { kind: "mismatch" }
  | { kind: "ready"; address?: string };

export declare function bindMailboxToQuanticId(
  mailIdentity: LocalIdentity | null | undefined,
  verifiedKeyId: string,
  now?: string,
): LocalIdentity;
