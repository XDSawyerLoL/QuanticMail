"use client";

import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { decryptEnvelope, encryptForRecipient, generateIdentityKeys, randomToken } from "@/lib/quantic/crypto";
import {
  deleteOutboxItem,
  getLocalContact,
  getLocalIdentity,
  listLocalMessages,
  listOutboxItems,
  saveLocalContact,
  saveLocalIdentity,
  saveLocalMessage,
  saveOutboxItem,
  type LocalIdentity,
  type LocalMessage,
  type LocalOutboxItem,
} from "@/lib/quantic/local-db";

type RelayEnvelope = {
  id: string;
  clientMessageId: string;
  from: string;
  to: string;
  ciphertext: string;
  iv: string;
  ephemeralPublicKey: JsonWebKey;
  createdAt: string;
};

type DeliveryReceipt = {
  id: string;
  clientMessageId: string;
  from: string;
  to: string;
  deliveredAt: string;
};

type PlainPayload = {
  id: string;
  from: string;
  to: string;
  subject: string;
  body: string;
  createdAt: string;
};

type ResolvedIdentity = {
  address: string;
  publicKey: JsonWebKey;
};

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  const data = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) throw new Error(data.error ?? `Erreur ${response.status}`);
  return data;
}

function normalizeHandle(value: string) {
  return value.trim().toLowerCase().replace(/@quantic$/i, "");
}

function samePublicKey(a: JsonWebKey, b: JsonWebKey) {
  return a.kty === b.kty && a.crv === b.crv && a.x === b.x && a.y === b.y;
}

export function QuanticNetworkApp() {
  const [identity, setIdentity] = useState<LocalIdentity | null>(null);
  const [messages, setMessages] = useState<LocalMessage[]>([]);
  const [outboxCount, setOutboxCount] = useState(0);
  const [handle, setHandle] = useState("");
  const [to, setTo] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [scope, setScope] = useState<"all" | "in" | "out">("all");
  const [busy, setBusy] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const syncingRef = useRef(false);

  const refreshLocal = useCallback(async () => {
    const [localMessages, outbox] = await Promise.all([listLocalMessages(), listOutboxItems()]);
    setMessages(localMessages);
    setOutboxCount(outbox.length);
  }, []);

  const publishIdentity = useCallback(async (local: LocalIdentity) => {
    await fetchJson("/api/quantic/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        handle: local.handle,
        publicKey: local.publicKey,
        authToken: local.authToken,
      }),
    });
  }, []);

  const pushOutboxItem = useCallback(async (local: LocalIdentity, item: LocalOutboxItem) => {
    await fetchJson("/api/quantic/send", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${local.authToken}`,
      },
      body: JSON.stringify({
        clientMessageId: item.id,
        from: item.from,
        to: item.to,
        ciphertext: item.ciphertext,
        iv: item.iv,
        ephemeralPublicKey: item.ephemeralPublicKey,
      }),
    });
    await saveOutboxItem({ ...item, lastAttemptAt: new Date().toISOString() });
  }, []);

  const flushOutbox = useCallback(
    async (local: LocalIdentity) => {
      const items = await listOutboxItems();
      const retryCutoff = Date.now() - 30_000;
      for (const item of items) {
        if (item.lastAttemptAt && Date.parse(item.lastAttemptAt) > retryCutoff) continue;
        try {
          await pushOutboxItem(local, item);
        } catch {
          // The encrypted envelope stays in IndexedDB and will be retried later.
        }
      }
    },
    [pushOutboxItem],
  );

  const resolveRecipient = useCallback(async (recipient: string): Promise<ResolvedIdentity> => {
    const cached = await getLocalContact(recipient);
    let remote: ResolvedIdentity;

    try {
      remote = await fetchJson<ResolvedIdentity>(
        `/api/quantic/resolve?handle=${encodeURIComponent(recipient)}`,
      );
    } catch (err) {
      if (cached) return { address: cached.address, publicKey: cached.publicKey };
      throw err;
    }

    if (cached && !samePublicKey(cached.publicKey, remote.publicKey)) {
      throw new Error(
        `Alerte sécurité : la clé de ${remote.address} a changé. Envoi bloqué pour éviter une usurpation.`,
      );
    }

    const now = new Date().toISOString();
    await saveLocalContact({
      handle: recipient,
      address: remote.address,
      publicKey: remote.publicKey,
      firstSeenAt: cached?.firstSeenAt ?? now,
      lastSeenAt: now,
    });
    return remote;
  }, []);

  const sync = useCallback(
    async (local = identity, quiet = false) => {
      if (!local || syncingRef.current) return;
      syncingRef.current = true;
      setSyncing(true);
      if (!quiet) {
        setError("");
        setNotice("Synchronisation…");
      }

      try {
        await publishIdentity(local);
        await flushOutbox(local);

        const pulled = await fetchJson<{ envelopes: RelayEnvelope[] }>(
          `/api/quantic/pull?handle=${encodeURIComponent(local.handle)}`,
          { headers: { authorization: `Bearer ${local.authToken}` } },
        );
        const acknowledged: string[] = [];

        for (const envelope of pulled.envelopes) {
          try {
            const payload = await decryptEnvelope<PlainPayload>(local.privateKey, envelope);
            if (
              payload.id !== envelope.clientMessageId ||
              payload.from !== envelope.from ||
              payload.to !== envelope.to
            ) {
              throw new Error("Enveloppe et contenu Quantic incohérents.");
            }
            await saveLocalMessage({
              id: payload.id,
              direction: "in",
              from: envelope.from,
              to: envelope.to,
              subject: payload.subject,
              body: payload.body,
              createdAt: payload.createdAt || envelope.createdAt,
            });
            acknowledged.push(envelope.id);
          } catch {
            // Keep the envelope on the relay if local decryption or validation fails.
          }
        }

        if (acknowledged.length) {
          await fetchJson("/api/quantic/ack", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              authorization: `Bearer ${local.authToken}`,
            },
            body: JSON.stringify({ handle: local.handle, ids: acknowledged }),
          });
        }

        const receiptPayload = await fetchJson<{ receipts: DeliveryReceipt[] }>(
          `/api/quantic/receipts?handle=${encodeURIComponent(local.handle)}`,
          { headers: { authorization: `Bearer ${local.authToken}` } },
        );
        const receiptIds: string[] = [];
        for (const receipt of receiptPayload.receipts) {
          await deleteOutboxItem(receipt.clientMessageId);
          receiptIds.push(receipt.id);
        }

        if (receiptIds.length) {
          await fetchJson("/api/quantic/receipts", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              authorization: `Bearer ${local.authToken}`,
            },
            body: JSON.stringify({ handle: local.handle, ids: receiptIds }),
          });
        }

        await refreshLocal();
        if (!quiet) {
          const parts = [];
          if (acknowledged.length) parts.push(`${acknowledged.length} reçu(s)`);
          if (receiptIds.length) parts.push(`${receiptIds.length} livré(s)`);
          setNotice(parts.length ? `${parts.join(" · ")}.` : "À jour.");
        }
      } catch (err) {
        if (!quiet) setError(err instanceof Error ? err.message : "Synchronisation impossible.");
      } finally {
        syncingRef.current = false;
        setSyncing(false);
      }
    },
    [flushOutbox, identity, publishIdentity, refreshLocal],
  );

  useEffect(() => {
    void (async () => {
      try {
        const local = await getLocalIdentity();
        setIdentity(local);
        await refreshLocal();
        if (local) await publishIdentity(local);
      } catch {
        setError("Impossible d’ouvrir le stockage local QuanticMail.");
      }
    })();
  }, [publishIdentity, refreshLocal]);

  useEffect(() => {
    if (!identity) return;
    void sync(identity, true);
    const timer = window.setInterval(() => void sync(identity, true), 12_000);
    return () => window.clearInterval(timer);
  }, [identity, sync]);

  async function createIdentity(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const clean = normalizeHandle(handle);
      if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(clean)) {
        throw new Error("Choisissez 3 à 32 caractères : lettres, chiffres, point, tiret ou underscore.");
      }
      const keys = await generateIdentityKeys();
      const local: LocalIdentity = {
        handle: clean,
        address: `${clean}@quantic`,
        publicKey: keys.publicKey,
        privateKey: keys.privateKey,
        authToken: randomToken(),
        createdAt: new Date().toISOString(),
      };
      await publishIdentity(local);
      await saveLocalIdentity(local);
      setIdentity(local);
      setNotice(`${local.address} est actif sur cet appareil.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Création impossible.");
    } finally {
      setBusy(false);
    }
  }

  async function sendMessage(event: FormEvent) {
    event.preventDefault();
    if (!identity) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const recipient = normalizeHandle(to);
      const resolved = await resolveRecipient(recipient);
      const createdAt = new Date().toISOString();
      const id = crypto.randomUUID();
      const payload: PlainPayload = {
        id,
        from: identity.address,
        to: resolved.address,
        subject: subject.trim() || "Sans objet",
        body,
        createdAt,
      };
      const encrypted = await encryptForRecipient(resolved.publicKey, payload);
      const outboxItem: LocalOutboxItem = {
        id,
        from: identity.handle,
        to: recipient,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        ephemeralPublicKey: encrypted.ephemeralPublicKey,
        createdAt,
      };

      await saveLocalMessage({ ...payload, direction: "out" });
      await saveOutboxItem(outboxItem);
      await refreshLocal();

      try {
        await pushOutboxItem(identity, outboxItem);
        setNotice(`Message chiffré transmis à ${resolved.address}. En attente de livraison.`);
      } catch {
        setNotice("Message conservé sur cet appareil. QuanticMail le renverra automatiquement.");
      }

      setTo("");
      setSubject("");
      setBody("");
      await refreshLocal();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Envoi impossible.");
    } finally {
      setBusy(false);
    }
  }

  const visibleMessages = useMemo(
    () => messages.filter((message) => scope === "all" || message.direction === scope),
    [messages, scope],
  );

  if (!identity) {
    return (
      <main className="qn-onboarding">
        <section className="qn-card qn-onboarding-card">
          <div className="qn-mark">Q</div>
          <p className="qn-kicker">QUANTIC SILLAGE</p>
          <h1>Crée ton identité Quantic.</h1>
          <p className="qn-lead">Pas de Gmail. Pas de domaine. Pas de quota de boîte. Ton appareil devient ta boîte.</p>
          <form onSubmit={createIdentity} className="qn-create-form">
            <label htmlFor="handle">Ton adresse</label>
            <div className="qn-address-input">
              <input id="handle" value={handle} onChange={(e) => setHandle(e.target.value)} placeholder="vnhz" autoComplete="off" />
              <span>@quantic</span>
            </div>
            <button disabled={busy}>{busy ? "Création…" : "Créer mon identité"}</button>
          </form>
          {error && <p className="qn-error">{error}</p>}
          <p className="qn-footnote">V0.6 alpha · la clé privée est créée et conservée uniquement dans le stockage local de ce navigateur.</p>
        </section>
      </main>
    );
  }

  return (
    <main className="qn-app">
      <header className="qn-topbar">
        <div className="qn-brand"><span className="qn-mark small">Q</span><div><strong>QuanticMail</strong><small>Quantic Network · V0.6 alpha</small></div></div>
        <div className="qn-identity">
          <button className="qn-address" onClick={() => void navigator.clipboard.writeText(identity.address)} title="Copier l’adresse">{identity.address}</button>
          <button className="qn-sync" onClick={() => void sync()} disabled={syncing}>{syncing ? "Synchro…" : "Synchroniser"}</button>
        </div>
      </header>

      <div className="qn-grid">
        <aside className="qn-sidebar qn-card">
          <p className="qn-kicker">BOÎTE LOCALE</p>
          <button className={scope === "all" ? "active" : ""} onClick={() => setScope("all")}>Tous <span>{messages.length}</span></button>
          <button className={scope === "in" ? "active" : ""} onClick={() => setScope("in")}>Reçus <span>{messages.filter((m) => m.direction === "in").length}</span></button>
          <button className={scope === "out" ? "active" : ""} onClick={() => setScope("out")}>Envoyés <span>{messages.filter((m) => m.direction === "out").length}</span></button>
          <div className="qn-local-note">
            <strong>Local-first</strong>
            <p>Les messages lisibles restent sur cet appareil.</p>
            <p>{outboxCount ? `${outboxCount} message(s) en attente d’accusé de livraison.` : "Aucun message en attente de livraison."}</p>
          </div>
        </aside>

        <section className="qn-card qn-inbox">
          <div className="qn-section-head"><div><p className="qn-kicker">MESSAGES</p><h2>{scope === "in" ? "Reçus" : scope === "out" ? "Envoyés" : "Tous les messages"}</h2></div><span>{visibleMessages.length}</span></div>
          <div className="qn-message-list">
            {visibleMessages.length === 0 ? <div className="qn-empty">Aucun message local pour le moment.</div> : visibleMessages.map((message) => (
              <article key={message.id} className="qn-message">
                <div className="qn-message-meta"><span className={`qn-direction ${message.direction}`}>{message.direction === "in" ? "REÇU" : "ENVOYÉ"}</span><time>{new Date(message.createdAt).toLocaleString("fr-FR")}</time></div>
                <h3>{message.subject}</h3>
                <p className="qn-correspondent">{message.direction === "in" ? `De ${message.from}` : `À ${message.to}`}</p>
                <p className="qn-body">{message.body}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="qn-card qn-compose">
          <p className="qn-kicker">NOUVEAU</p>
          <h2>Message Quantic</h2>
          <form onSubmit={sendMessage}>
            <label>À</label>
            <div className="qn-address-input compact"><input value={to} onChange={(e) => setTo(e.target.value)} placeholder="marie" required /><span>@quantic</span></div>
            <label>Objet</label>
            <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Sans objet" />
            <label>Message</label>
            <textarea value={body} onChange={(e) => setBody(e.target.value)} placeholder="Écrire…" rows={12} required />
            <button disabled={busy}>{busy ? "Chiffrement…" : "Chiffrer et envoyer"}</button>
          </form>
          {(error || notice) && <p className={error ? "qn-error" : "qn-notice"}>{error || notice}</p>}
          <p className="qn-footnote">Le texte est chiffré dans ton navigateur. Une copie chiffrée reste dans la file locale jusqu’à l’accusé de livraison.</p>
        </section>
      </div>
    </main>
  );
}
