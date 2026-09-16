"use client";

import { FormEvent, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import type { MailSnapshot } from "@/lib/mail/service";

function displayTime(value: string) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const now = new Date();
  const sameDay = date.toDateString() === now.toDateString();
  return sameDay
    ? new Intl.DateTimeFormat("fr-FR", { hour: "2-digit", minute: "2-digit" }).format(date)
    : new Intl.DateTimeFormat("fr-FR", { day: "2-digit", month: "short" }).format(date);
}

function initials(email: string) {
  const local = email.split("@")[0] || "QM";
  return local
    .split(/[._-]/)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() || "")
    .join("") || "QM";
}

export function MailShell({ initialSnapshot }: { initialSnapshot: MailSnapshot }) {
  const router = useRouter();
  const [snapshot, setSnapshot] = useState(initialSnapshot);
  const [selectedId, setSelectedId] = useState(initialSnapshot.messages[0]?.id || "");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [composerOpen, setComposerOpen] = useState(false);
  const [to, setTo] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [sendState, setSendState] = useState<"idle" | "sending" | "sent">("idle");
  const [sendError, setSendError] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return snapshot.messages;
    return snapshot.messages.filter((mail) =>
      [mail.sender, mail.senderEmail, mail.subject, mail.preview].some((value) =>
        value.toLowerCase().includes(q),
      ),
    );
  }, [query, snapshot.messages]);

  const selected = snapshot.messages.find((mail) => mail.id === selectedId) ?? snapshot.messages[0];
  const activeMailbox = snapshot.mailboxes.find((mailbox) => mailbox.id === snapshot.activeMailboxId);

  async function loadMailbox(mailboxId = snapshot.activeMailboxId) {
    if (!mailboxId) return;
    setLoading(true);
    setLoadError("");
    try {
      const response = await fetch(`/api/mail?mailboxId=${encodeURIComponent(mailboxId)}`, {
        cache: "no-store",
      });
      const data = (await response.json()) as MailSnapshot & { error?: string };
      if (response.status === 401) {
        router.refresh();
        return;
      }
      if (!response.ok) throw new Error(data.error || "Impossible de charger le dossier.");
      setSnapshot(data);
      setSelectedId(data.messages[0]?.id || "");
      setQuery("");
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Chargement impossible.");
    } finally {
      setLoading(false);
    }
  }

  async function logout() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.refresh();
  }

  async function send(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSendState("sending");
    setSendError("");
    try {
      const response = await fetch("/api/mail/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ to, subject, body }),
      });
      const data = (await response.json()) as { error?: string };
      if (response.status === 401) {
        router.refresh();
        return;
      }
      if (!response.ok) throw new Error(data.error || "Échec de l’envoi.");
      setSendState("sent");
      setTo("");
      setSubject("");
      setBody("");
      window.setTimeout(() => {
        setComposerOpen(false);
        setSendState("idle");
      }, 700);
    } catch (error) {
      setSendError(error instanceof Error ? error.message : "Échec de l’envoi.");
      setSendState("idle");
    }
  }

  return (
    <main className="mail-app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">Q</div>
          <div>
            <strong>QuanticMail</strong>
            <span>by Quantic Sillage</span>
          </div>
        </div>

        <button className="compose" onClick={() => setComposerOpen(true)}>＋ Nouveau message</button>

        <nav className="folders" aria-label="Dossiers">
          {snapshot.mailboxes.map((mailbox) => (
            <button
              key={mailbox.id}
              className={snapshot.activeMailboxId === mailbox.id ? "folder active" : "folder"}
              onClick={() => loadMailbox(mailbox.id)}
              disabled={loading}
            >
              <span>{mailbox.name}</span>
              {mailbox.unreadEmails > 0 && <small>{mailbox.unreadEmails}</small>}
            </button>
          ))}
        </nav>

        <div className="account-card">
          <div className="avatar">{initials(snapshot.accountEmail)}</div>
          <div className="account-details">
            <strong>{snapshot.accountEmail.split("@")[0]}</strong>
            <span>{snapshot.accountEmail}</span>
            <button className="logout-link" onClick={logout}>Déconnexion</button>
          </div>
        </div>
      </aside>

      <section className="mail-list-panel">
        <header className="toolbar">
          <div>
            <span className="eyebrow">QuanticMail</span>
            <h1>{activeMailbox?.name || "Messagerie"}</h1>
          </div>
          <div className="toolbar-actions">
            <button aria-label="Actualiser" onClick={() => loadMailbox()} disabled={loading}>↻</button>
          </div>
        </header>

        <label className="search">
          <span>⌕</span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Rechercher dans les messages chargés"
          />
        </label>

        {loadError && <p className="panel-error">{loadError}</p>}
        {loading && <p className="panel-status">Chargement…</p>}

        <div className="message-list">
          {!loading && filtered.length === 0 && (
            <div className="empty-state">Aucun message dans ce dossier.</div>
          )}
          {filtered.map((mail) => (
            <button
              key={mail.id}
              className={selected?.id === mail.id ? "message selected" : "message"}
              onClick={() => setSelectedId(mail.id)}
            >
              <div className="message-row">
                <strong>{mail.sender}</strong>
                <time>{displayTime(mail.receivedAt)}</time>
              </div>
              <div className="message-row subject-row">
                <span className={mail.unread ? "unread-dot" : "read-dot"} />
                <b>{mail.subject}</b>
                {mail.starred && <span className="star">★</span>}
              </div>
              <p>{mail.preview}</p>
            </button>
          ))}
        </div>
      </section>

      <article className="reader">
        {selected ? (
          <>
            <header className="reader-header">
              <div>
                <span className="eyebrow">Message</span>
                <h2>{selected.subject}</h2>
              </div>
            </header>

            <div className="sender-line">
              <div className="avatar large">{initials(selected.senderEmail || selected.sender)}</div>
              <div>
                <strong>{selected.sender}</strong>
                <span>{selected.senderEmail} · à {snapshot.accountEmail}</span>
              </div>
              <time>{displayTime(selected.receivedAt)}</time>
            </div>

            <div className="message-body live-body">{selected.body || selected.preview}</div>

            <div className="reply-box">
              <button onClick={() => {
                setTo(selected.senderEmail);
                setSubject(selected.subject.startsWith("Re:") ? selected.subject : `Re: ${selected.subject}`);
                setComposerOpen(true);
              }}>↩ Répondre</button>
            </div>
          </>
        ) : (
          <div className="reader-empty">
            <span className="eyebrow">QuanticMail</span>
            <h2>Aucun message sélectionné</h2>
          </div>
        )}
      </article>

      {composerOpen && (
        <div className="composer-backdrop" role="presentation" onMouseDown={(event) => {
          if (event.target === event.currentTarget && sendState !== "sending") setComposerOpen(false);
        }}>
          <section className="composer" role="dialog" aria-modal="true" aria-label="Nouveau message">
            <header>
              <div>
                <span className="eyebrow">QuanticMail</span>
                <h2>Nouveau message</h2>
              </div>
              <button className="composer-close" onClick={() => setComposerOpen(false)} disabled={sendState === "sending"}>×</button>
            </header>
            <form onSubmit={send}>
              <label>
                À
                <input type="email" value={to} onChange={(event) => setTo(event.target.value)} required />
              </label>
              <label>
                Objet
                <input value={subject} onChange={(event) => setSubject(event.target.value)} />
              </label>
              <label className="composer-body-label">
                Message
                <textarea value={body} onChange={(event) => setBody(event.target.value)} required />
              </label>
              {sendError && <p className="form-error" role="alert">{sendError}</p>}
              <footer>
                <span>{sendState === "sent" ? "Message envoyé." : `Depuis ${snapshot.accountEmail}`}</span>
                <button type="submit" disabled={sendState !== "idle"}>
                  {sendState === "sending" ? "Envoi…" : sendState === "sent" ? "Envoyé ✓" : "Envoyer"}
                </button>
              </footer>
            </form>
          </section>
        </div>
      )}
    </main>
  );
}
