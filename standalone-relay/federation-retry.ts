import { postFederationReceipt } from "./federation-client.ts";
import {
  pendingFederationReceipts,
  queuePendingFederationReceipt,
  removePendingFederationReceipt,
} from "./federation-state.ts";
import { RelayRuntime } from "./runtime.ts";

export async function retryPendingFederationReceipts(runtime: RelayRuntime) {
  const pending = await runtime.read(() => pendingFederationReceipts());
  for (const item of pending) {
    if (Date.parse(item.nextAttemptAt) > Date.now()) continue;
    try {
      await postFederationReceipt(item.receipt, item.originEndpoint);
      await runtime.mutate(() => removePendingFederationReceipt(item.federationId));
    } catch {
      await runtime.mutate(() =>
        queuePendingFederationReceipt({
          ...item,
          attempts: item.attempts + 1,
          nextAttemptAt: new Date(
            Date.now() + Math.min(60_000, 2_000 * 2 ** Math.min(item.attempts, 5)),
          ).toISOString(),
        }),
      );
    }
  }
}
