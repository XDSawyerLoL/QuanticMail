"use client";

import Link from "next/link";
import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  DEFAULT_RELAY_ENDPOINTS,
  buildRelayUrl,
  getActiveRelayId,
  getRelayEndpoints,
  normalizeRelayBaseUrl,
  saveActiveRelayId,
  saveRelayEndpoints,
  type RelayEndpoint,
} from "@/lib/quantic/relay-client";

type RelayStatus = { state: "idle" | "checking" | "ok" | "error"; message?: string };

export function RelaySettings() {
  const [relays, setRelays] = useState<RelayEndpoint[]>([]);
  const [activeRelayId, setActiveRelayId] = useState<string | null>(null);
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [statuses, setStatuses] = useState<Record<string, RelayStatus>>({});

  useEffect(() => {
    setRelays(getRelayEndpoints());
    setActiveRelayId(getActiveRelayId());
  }, []);

  const sortedRelays = useMemo(
    () => [...relays].sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id)),
    [relays],
  );

  function persist(next: RelayEndpoint[], message?: string) {
    saveRelayEndpoints(next);
    const activeStillAvailable = activeRelayId && next.some((relay) => relay.id === activeRelayId && relay.enabled);
    if (!activeStillAvailable && activeRelayId) {
      saveActiveRelayId(null);
      setActiveRelayId(null);
    }
    setRelays(next);
    setError("");
    if (message) setNotice(message);
  }

  function addRelay(event: FormEvent) {
    event.preventDefault();
    setError("");
    setNotice("");
    try {
      const baseUrl = normalizeRelayBaseUrl(url);
      if (!baseUrl) throw new Error("Indique l’URL HTTPS du relais à ajouter.");
      if (relays.some((relay) => normalizeRelayBaseUrl(relay.baseUrl) === baseUrl)) {
        throw new Error("Ce relais est déjà dans la liste.");
      }
      const parsed = new URL(baseUrl);
      const next: RelayEndpoint[] = [
        ...relays,
        {
          id: `relay-${crypto.randomUUID()}`,
          label: parsed.hostname,
          baseUrl,
          priority: Math.max(0, ...relays.map((relay) => relay.priority)) + 10,
          enabled: true,
        },
      ];
      persist(next, `${parsed.hostname} ajouté au réseau local.`);
      setUrl("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Relais invalide.");
    }
  }

  function activateRelay(id: string) {
    const relay = relays.find((item) => item.id === id);
    if (!relay?.enabled) {
      setError("Active ce relais avant de l’utiliser.");
      return;
    }
    saveActiveRelayId(id);
    setActiveRelayId(id);
    setError("");
    setNotice(`${relay.label} devient le relais actif de cet appareil.`);
  }

  function toggleRelay(id: string) {
    const next = relays.map((relay) => relay.id === id ? { ...relay, enabled: !relay.enabled } : relay);
    if (!next.some((relay) => relay.enabled)) {
      setError("Au moins un relais doit rester actif.");
      return;
    }
    persist(next);
  }

  function removeRelay(id: string) {
    if (relays.length <= 1) {
      setError("Ajoute d’abord un autre relais avant de supprimer le dernier.");
      return;
    }
    persist(relays.filter((relay) => relay.id !== id), "Relais supprimé de cet appareil.");
  }

  function moveRelay(id: string, direction: -1 | 1) {
    const ordered = [...sortedRelays];
    const index = ordered.findIndex((relay) => relay.id === id);
    const target = index + direction;
    if (index < 0 || target < 0 || target >= ordered.length) return;
    [ordered[index], ordered[target]] = [ordered[target], ordered[index]];
    persist(ordered.map((relay, position) => ({ ...relay, priority: (position + 1) * 10 })));
  }

  async function testRelay(relay: RelayEndpoint) {
    setStatuses((current) => ({ ...current, [relay.id]: { state: "checking" } }));
    try {
      const response = await fetch(buildRelayUrl(relay, "/api/quantic/health"), {
        cache: "no-store",
        headers: relay.baseUrl ? undefined : { "x-quantic-direct-relay": "1" },
      });
      const data = (await response.json().catch(() => ({}))) as { protocol?: string; service?: string; error?: string };
      if (!response.ok) throw new Error(data.error ?? `HTTP ${response.status}`);
      if (data.protocol !== "quantic-relay/1") throw new Error("Protocole Quantic Relay V1 non détecté.");
      setStatuses((current) => ({
        ...current,
        [relay.id]: { state: "ok", message: data.service ?? "Relais Quantic V1 disponible" },
      }));
    } catch (err) {
      setStatuses((current) => ({
        ...current,
        [relay.id]: { state: "error", message: err instanceof Error ? err.message : "Injoignable" },
      }));
    }
  }

  function resetRelays() {
    saveActiveRelayId(null);
    setActiveRelayId(null);
    persist(DEFAULT_RELAY_ENDPOINTS.map((relay) => ({ ...relay })), "Configuration remise sur le relais de cette instance.");
    setStatuses({});
  }

  return (
    <main className="qn-onboarding qn-vault-page">
      <section className="qn-card qn-vault-card">
        <div className="qn-vault-head">
          <div>
            <p className="qn-kicker">QUANTIC NETWORK V1</p>
            <h1>Relais contrôlés par l’utilisateur.</h1>
            <p className="qn-lead">
              L’identité Quantic reste la même. Cet appareil choisit localement quels relais peuvent transporter ses enveloppes chiffrées et dans quel ordre.
            </p>
          </div>
          <Link className="qn-back-link" href="/">Retour à QuanticMail</Link>
        </div>

        <div className="qn-vault-grid single">
          <section className="qn-vault-section">
            <p className="qn-kicker">MES RELAIS</p>
            <div className="qn-device-list">
              {sortedRelays.map((relay, index) => {
                const status = statuses[relay.id] ?? { state: "idle" as const };
                const isActive = activeRelayId === relay.id;
                return (
                  <div className="qn-device-row" key={relay.id}>
                    <div>
                      <strong>{relay.label}{isActive ? " · RELAIS ACTIF" : ""}</strong>
                      <code>{relay.baseUrl || "Cette instance QuanticMail"}</code>
                      <small>
                        Priorité {index + 1} · {relay.enabled ? "actif" : "désactivé"}
                        {status.state === "checking" ? " · test…" : ""}
                        {status.state === "ok" ? ` · OK${status.message ? ` — ${status.message}` : ""}` : ""}
                        {status.state === "error" ? ` · erreur — ${status.message ?? "injoignable"}` : ""}
                      </small>
                    </div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      <button type="button" onClick={() => moveRelay(relay.id, -1)} disabled={index === 0}>↑</button>
                      <button type="button" onClick={() => moveRelay(relay.id, 1)} disabled={index === sortedRelays.length - 1}>↓</button>
                      <button type="button" onClick={() => void testRelay(relay)}>Tester</button>
                      <button type="button" onClick={() => activateRelay(relay.id)} disabled={isActive || !relay.enabled}>Utiliser</button>
                      <button type="button" onClick={() => toggleRelay(relay.id)}>{relay.enabled ? "Désactiver" : "Activer"}</button>
                      <button type="button" onClick={() => removeRelay(relay.id)}>Supprimer</button>
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          <section className="qn-vault-section">
            <p className="qn-kicker">AJOUTER UN RELAIS</p>
            <form className="qn-vault-form" onSubmit={addRelay}>
              <label htmlFor="relay-url">Adresse du relais Quantic V1</label>
              <input
                id="relay-url"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://relay.example.org"
                autoComplete="off"
              />
              <button type="submit">Ajouter à cet appareil</button>
            </form>
            <button type="button" onClick={resetRelays} style={{ marginTop: 12 }}>Réinitialiser la liste</button>
            {error && <p className="qn-error">{error}</p>}
            {notice && <p className="qn-notice">{notice}</p>}
            <p className="qn-footnote">
              Cette liste est stockée uniquement dans ce navigateur. Après une bascule, QuanticMail reste sur le relais qui a répondu afin de garder messages, reçus et accusés cohérents. Tu peux changer de relais actif ici. Aucun relais ne reçoit tes clés privées ni le contenu en clair.
            </p>
          </section>
        </div>
      </section>
    </main>
  );
}
