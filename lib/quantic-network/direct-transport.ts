import { decryptEnvelope, encryptForRecipient } from "@/lib/quantic/crypto";
import { getLocalIdentity, type LocalIdentity } from "@/lib/quantic/local-db";
import {
  getActiveRelayId,
  getRelayEndpoints,
  orderedRelays,
  relayFetchJson,
  type RelayEndpoint,
} from "@/lib/quantic/relay-client";
import type { DeliveryReceipt, RelayEnvelope } from "@/lib/quantic/relay";
import {
  createDirectEnvelopeFrame,
  createDirectReceiptFrame,
  parseDirectFrame,
} from "./direct-wire.mjs";
import {
  deleteDirectEnvelopes,
  deleteDirectReceipts,
  listDirectEnvelopes,
  listDirectReceipts,
  putDirectEnvelope,
  putDirectReceipt,
} from "./direct-store";

export type DirectSendBody = {
  clientMessageId: string;
  from: string;
  fromDeviceId: string;
  to: string;
  toDeviceId: string;
  ciphertext: string;
  iv: string;
  ephemeralPublicKey: JsonWebKey;
  [key: string]: unknown;
};

type ResolvedDevice = { deviceId: string; publicKey: JsonWebKey };
type ResolvedIdentity = { canonicalAddress: string; devices?: ResolvedDevice[]; publicKey: JsonWebKey };
type SignalType = "offer" | "answer" | "ice" | "cancel" | "receipt";
type SignalRecord = {
  id: string;
  from: string;
  fromDeviceId: string;
  to: string;
  toDeviceId: string;
  type: SignalType;
  encrypted: { ciphertext: string; iv: string; ephemeralPublicKey: JsonWebKey };
};
type SignalPayload = {
  sessionId: string;
  description?: RTCSessionDescriptionInit;
  candidate?: RTCIceCandidateInit;
  frame?: unknown;
};

type Session = {
  id: string;
  pc: RTCPeerConnection;
  channel: RTCDataChannel | null;
  peerCanonicalAddress: string;
  peerDeviceId: string;
  peerPublicKey: JsonWebKey;
  signalRelay: RelayEndpoint | null;
  authToken: string;
  localCanonicalAddress: string;
  localDeviceId: string;
  pendingIce: RTCIceCandidateInit[];
  outboundIce: RTCIceCandidateInit[];
};

type DirectTransportContext = {
  fetchImpl: typeof fetch;
};

const POLL_INTERVAL_MS = 1_500;
const CONNECT_TIMEOUT_MS = 2_500;
const STORE_ACK_TIMEOUT_MS = 1_500;
const CONTROL_FORMAT = "quantic-direct-control";

function rtcAvailable() {
  return typeof window !== "undefined" && typeof RTCPeerConnection !== "undefined";
}

function waitForEvent(target: EventTarget, eventName: string, timeoutMs: number) {
  return new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      target.removeEventListener(eventName, onEvent);
      reject(new Error(`Timeout ${eventName}`));
    }, timeoutMs);
    const onEvent = () => {
      window.clearTimeout(timer);
      target.removeEventListener(eventName, onEvent);
      resolve();
    };
    target.addEventListener(eventName, onEvent, { once: true });
  });
}

function stunServers() {
  const configured = typeof process !== "undefined" ? process.env.NEXT_PUBLIC_QUANTIC_STUN_SERVERS : undefined;
  const urls = configured?.split(",").map((item) => item.trim()).filter(Boolean) ?? [];
  return urls.length ? [{ urls }] : [];
}

function peerConnection() {
  return new RTCPeerConnection({ iceServers: stunServers() });
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

class DirectTransportCoordinator {
  private context: DirectTransportContext | null = null;
  private timer: number | null = null;
  private polling = false;
  private sessions = new Map<string, Session>();
  private pendingStored = new Map<string, () => void>();
  private pendingInboundIce = new Map<string, RTCIceCandidateInit[]>();

  start(context: DirectTransportContext) {
    this.context = context;
    if (!rtcAvailable() || this.timer !== null) return;
    void this.pollSignals();
    this.timer = window.setInterval(() => { void this.pollSignals(); }, POLL_INTERVAL_MS);
  }

  private async resolveDevice(
    relays: RelayEndpoint[],
    canonicalAddress: string,
    deviceId: string,
    preferredRelayId?: string | null,
  ) {
    if (!this.context) throw new Error("Transport direct non initialisé.");
    const { data, relay } = await relayFetchJson<ResolvedIdentity>(
      relays,
      `/api/quantic/resolve?handle=${encodeURIComponent(canonicalAddress)}`,
      undefined,
      {
        fetchImpl: this.context.fetchImpl,
        preferredRelayId,
        retryStatuses: [404],
      },
    );
    const device = data.devices?.find((candidate) => candidate.deviceId === deviceId)
      ?? (data.devices?.length ? null : { deviceId, publicKey: data.publicKey });
    if (!device) throw new Error("Appareil direct destinataire introuvable.");
    return { device, relay };
  }

  private async sendSignal(
    relays: RelayEndpoint[],
    local: Pick<LocalIdentity, "canonicalAddress" | "deviceId" | "authToken">,
    target: { canonicalAddress: string; deviceId: string; publicKey: JsonWebKey },
    type: SignalType,
    payload: SignalPayload,
    preferredRelayId?: string | null,
  ) {
    if (!this.context || !local.canonicalAddress || !local.deviceId) throw new Error("Signal direct incomplet.");
    const encrypted = await encryptForRecipient(target.publicKey, payload);
    return relayFetchJson<{ accepted: boolean; targetOnline?: boolean }>(
      relays,
      "/api/quantic/direct/send",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${local.authToken}`,
        },
        body: JSON.stringify({
          from: local.canonicalAddress,
          fromDeviceId: local.deviceId,
          to: target.canonicalAddress,
          toDeviceId: target.deviceId,
          type,
          encrypted,
        }),
      },
      { fetchImpl: this.context.fetchImpl, preferredRelayId },
    );
  }

  private configureSession(session: Session) {
    session.pc.onicecandidate = (event) => {
      if (!event.candidate) return;
      const candidate = event.candidate.toJSON();
      if (!session.signalRelay) {
        session.outboundIce.push(candidate);
        return;
      }
      void this.sendSignal(
        [session.signalRelay],
        {
          canonicalAddress: session.localCanonicalAddress,
          deviceId: session.localDeviceId,
          authToken: session.authToken,
        },
        {
          canonicalAddress: session.peerCanonicalAddress,
          deviceId: session.peerDeviceId,
          publicKey: session.peerPublicKey,
        },
        "ice",
        { sessionId: session.id, candidate },
        session.signalRelay.id,
      ).catch(() => undefined);
    };
    session.pc.ondatachannel = (event) => {
      session.channel = event.channel;
      this.bindChannel(session, event.channel);
    };
  }

  private bindChannel(session: Session, channel: RTCDataChannel) {
    channel.onmessage = (event) => {
      void (async () => {
        try {
          const raw = typeof event.data === "string" ? event.data : "";
          const maybeControl = JSON.parse(raw) as { format?: string; type?: string; envelopeId?: string };
          if (maybeControl.format === CONTROL_FORMAT && maybeControl.type === "stored" && maybeControl.envelopeId) {
            this.pendingStored.get(maybeControl.envelopeId)?.();
            this.pendingStored.delete(maybeControl.envelopeId);
            return;
          }
          const frame = parseDirectFrame(raw) as { type: "envelope" | "receipt"; payload: RelayEnvelope | DeliveryReceipt };
          if (frame.type === "envelope") {
            const identity = await getLocalIdentity();
            const envelope = frame.payload as RelayEnvelope;
            if (
              !identity?.canonicalAddress ||
              !identity.deviceId ||
              envelope.to !== identity.canonicalAddress ||
              envelope.toDeviceId !== identity.deviceId
            ) return;
            await putDirectEnvelope(envelope);
            channel.send(JSON.stringify({ format: CONTROL_FORMAT, version: 1, type: "stored", envelopeId: envelope.id }));
          } else {
            await putDirectReceipt(frame.payload as DeliveryReceipt);
          }
        } catch {
          // Invalid direct frames are dropped and never reach the local mailbox.
        }
      })();
    };
  }

  private async flushPendingIce(session: Session) {
    const pending = this.pendingInboundIce.get(session.id) ?? [];
    this.pendingInboundIce.delete(session.id);
    for (const candidate of pending) await session.pc.addIceCandidate(candidate).catch(() => undefined);
  }

  private async processSignal(signal: SignalRecord, relay: RelayEndpoint, local: LocalIdentity) {
    if (!local.privateKey || !local.canonicalAddress || !local.deviceId) return;
    let payload: SignalPayload;
    try {
      payload = await decryptEnvelope<SignalPayload>(local.privateKey, signal.encrypted);
    } catch {
      return;
    }
    if (!payload?.sessionId || typeof payload.sessionId !== "string") return;

    if (signal.type === "receipt") {
      if (!payload.frame) return;
      try {
        const frame = parseDirectFrame(payload.frame) as { type: string; payload: DeliveryReceipt };
        if (frame.type === "receipt") await putDirectReceipt(frame.payload);
      } catch {
        // Tampered receipt frame.
      }
      return;
    }

    if (signal.type === "ice") {
      if (!payload.candidate) return;
      const session = this.sessions.get(payload.sessionId);
      if (session) await session.pc.addIceCandidate(payload.candidate).catch(() => undefined);
      else {
        const pending = this.pendingInboundIce.get(payload.sessionId) ?? [];
        if (pending.length < 64) pending.push(payload.candidate);
        this.pendingInboundIce.set(payload.sessionId, pending);
      }
      return;
    }

    if (signal.type === "cancel") {
      const session = this.sessions.get(payload.sessionId);
      session?.pc.close();
      this.sessions.delete(payload.sessionId);
      return;
    }

    if (signal.type === "answer") {
      const session = this.sessions.get(payload.sessionId);
      if (!session || !payload.description) return;
      await session.pc.setRemoteDescription(payload.description);
      await this.flushPendingIce(session);
      return;
    }

    if (signal.type !== "offer" || !payload.description) return;
    const { device: peer } = await this.resolveDevice([relay], signal.from, signal.fromDeviceId, relay.id);
    const session: Session = {
      id: payload.sessionId,
      pc: peerConnection(),
      channel: null,
      peerCanonicalAddress: signal.from,
      peerDeviceId: signal.fromDeviceId,
      peerPublicKey: peer.publicKey,
      signalRelay: relay,
      authToken: local.authToken,
      localCanonicalAddress: local.canonicalAddress,
      localDeviceId: local.deviceId,
      pendingIce: [],
      outboundIce: [],
    };
    this.sessions.set(session.id, session);
    this.configureSession(session);
    await session.pc.setRemoteDescription(payload.description);
    await this.flushPendingIce(session);
    const answer = await session.pc.createAnswer();
    await session.pc.setLocalDescription(answer);
    await this.sendSignal(
      [relay],
      local,
      { canonicalAddress: signal.from, deviceId: signal.fromDeviceId, publicKey: peer.publicKey },
      "answer",
      { sessionId: session.id, description: session.pc.localDescription ?? answer },
      relay.id,
    );
  }

  private async pollSignals() {
    if (this.polling || !this.context || !rtcAvailable()) return;
    this.polling = true;
    try {
      const local = await getLocalIdentity();
      if (!local?.canonicalAddress || !local.deviceId) return;
      const relays = orderedRelays(getRelayEndpoints(), getActiveRelayId());
      const polls = relays.map(async (relay) => {
        try {
          const { data } = await relayFetchJson<{ signals: SignalRecord[] }>(
            [relay],
            `/api/quantic/direct/poll?handle=${encodeURIComponent(local.canonicalAddress!)}&deviceId=${encodeURIComponent(local.deviceId!)}`,
            { headers: { authorization: `Bearer ${local.authToken}` } },
            { fetchImpl: this.context!.fetchImpl, preferredRelayId: relay.id },
          );
          for (const signal of data.signals ?? []) await this.processSignal(signal, relay, local);
        } catch {
          // Direct transport is optional; normal relay sync remains authoritative fallback.
        }
      });
      await Promise.allSettled(polls);
    } finally {
      this.polling = false;
    }
  }

  async trySend(body: DirectSendBody, authToken: string) {
    if (!this.context || !rtcAvailable()) return { status: "fallback" as const };
    const local = await getLocalIdentity();
    if (
      !local?.canonicalAddress ||
      !local.deviceId ||
      local.canonicalAddress !== body.from ||
      local.deviceId !== body.fromDeviceId ||
      local.authToken !== authToken
    ) return { status: "fallback" as const };

    const relays = orderedRelays(getRelayEndpoints(), getActiveRelayId());
    if (!relays.length) return { status: "fallback" as const };
    let session: Session | null = null;
    try {
      const resolved = await this.resolveDevice(relays, body.to, body.toDeviceId, getActiveRelayId());
      const sessionId = crypto.randomUUID();
      session = {
        id: sessionId,
        pc: peerConnection(),
        channel: null,
        peerCanonicalAddress: body.to,
        peerDeviceId: body.toDeviceId,
        peerPublicKey: resolved.device.publicKey,
        signalRelay: resolved.relay,
        authToken,
        localCanonicalAddress: body.from,
        localDeviceId: body.fromDeviceId,
        pendingIce: [],
        outboundIce: [],
      };
      this.sessions.set(sessionId, session);
      this.configureSession(session);
      const channel = session.pc.createDataChannel("quantic", { ordered: true });
      session.channel = channel;
      this.bindChannel(session, channel);
      const offer = await session.pc.createOffer();
      await session.pc.setLocalDescription(offer);
      const signalResult = await this.sendSignal(
        relays,
        local,
        { canonicalAddress: body.to, deviceId: body.toDeviceId, publicKey: resolved.device.publicKey },
        "offer",
        { sessionId, description: session.pc.localDescription ?? offer },
        resolved.relay.id,
      );
      session.signalRelay = signalResult.relay;
      for (const candidate of session.outboundIce.splice(0)) {
        await this.sendSignal(
          [session.signalRelay],
          local,
          { canonicalAddress: body.to, deviceId: body.toDeviceId, publicKey: resolved.device.publicKey },
          "ice",
          { sessionId, candidate },
          session.signalRelay.id,
        ).catch(() => undefined);
      }
      if (channel.readyState !== "open") await waitForEvent(channel, "open", CONNECT_TIMEOUT_MS);

      const envelope: RelayEnvelope & Record<string, unknown> = {
        ...clone(body),
        id: `dmsg-${crypto.randomUUID()}`,
        createdAt: new Date().toISOString(),
      } as RelayEnvelope & Record<string, unknown>;
      const stored = new Promise<void>((resolve, reject) => {
        const timer = window.setTimeout(() => {
          this.pendingStored.delete(envelope.id);
          reject(new Error("Direct storage acknowledgement timeout"));
        }, STORE_ACK_TIMEOUT_MS);
        this.pendingStored.set(envelope.id, () => {
          window.clearTimeout(timer);
          resolve();
        });
      });
      channel.send(JSON.stringify(createDirectEnvelopeFrame(envelope)));
      await stored;
      return { status: "delivered-direct" as const, envelopeId: envelope.id };
    } catch {
      session?.pc.close();
      if (session) this.sessions.delete(session.id);
      return { status: "fallback" as const };
    }
  }

  async acknowledgeEnvelopes(ids: string[]) {
    if (!this.context || !ids.length) return new Set<string>();
    const local = await getLocalIdentity();
    if (!local?.canonicalAddress || !local.deviceId) return new Set<string>();
    const direct = (await listDirectEnvelopes()).filter((item) => ids.includes(item.id));
    const handled = new Set(direct.map((item) => item.id));
    const relays = orderedRelays(getRelayEndpoints(), getActiveRelayId());
    for (const envelope of direct) {
      const receipt: DeliveryReceipt = {
        id: `dreceipt-${crypto.randomUUID()}`,
        clientMessageId: envelope.clientMessageId,
        from: envelope.to,
        fromDeviceId: envelope.toDeviceId,
        to: envelope.from,
        toDeviceId: envelope.fromDeviceId,
        deliveredAt: new Date().toISOString(),
      };
      const openSession = [...this.sessions.values()].find((candidate) =>
        candidate.peerCanonicalAddress === envelope.from &&
        candidate.peerDeviceId === envelope.fromDeviceId &&
        candidate.channel?.readyState === "open"
      );
      if (openSession?.channel) {
        try {
          openSession.channel.send(JSON.stringify(createDirectReceiptFrame(receipt)));
          continue;
        } catch {
          // Fall through to encrypted signaling receipt.
        }
      }
      try {
        const resolved = await this.resolveDevice(relays, envelope.from, envelope.fromDeviceId, getActiveRelayId());
        await this.sendSignal(
          relays,
          local,
          { canonicalAddress: envelope.from, deviceId: envelope.fromDeviceId, publicKey: resolved.device.publicKey },
          "receipt",
          { sessionId: `receipt-${receipt.id}`, frame: createDirectReceiptFrame(receipt) },
          resolved.relay.id,
        );
      } catch {
        // Sender outbox remains durable and will fall back to relay delivery.
      }
    }
    await deleteDirectEnvelopes([...handled]);
    return handled;
  }

  async acknowledgeReceipts(ids: string[]) {
    const direct = (await listDirectReceipts()).filter((item) => ids.includes(item.id));
    await deleteDirectReceipts(direct.map((item) => item.id));
    return new Set(direct.map((item) => item.id));
  }
}

const coordinator = new DirectTransportCoordinator();

export function startDirectTransport(fetchImpl: typeof fetch) {
  coordinator.start({ fetchImpl });
}

export function tryDirectSend(body: DirectSendBody, authToken: string) {
  return coordinator.trySend(body, authToken);
}

export function acknowledgeDirectEnvelopes(ids: string[]) {
  return coordinator.acknowledgeEnvelopes(ids);
}

export function acknowledgeDirectReceipts(ids: string[]) {
  return coordinator.acknowledgeReceipts(ids);
}

export { listDirectEnvelopes, listDirectReceipts } from "./direct-store";
