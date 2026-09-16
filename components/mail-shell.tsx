"use client";

import { useMemo, useState } from "react";

type Mail = {
  id: number;
  sender: string;
  subject: string;
  preview: string;
  time: string;
  unread?: boolean;
  starred?: boolean;
};

const mails: Mail[] = [
  {
    id: 1,
    sender: "Quantic Sillage",
    subject: "Bienvenue dans QuanticMail",
    preview: "Votre nouvelle messagerie est prête à être connectée à votre domaine.",
    time: "14:32",
    unread: true,
    starred: true,
  },
  {
    id: 2,
    sender: "Providence",
    subject: "Rapport hebdomadaire",
    preview: "Le rapport Providence est disponible pour consultation.",
    time: "11:08",
    unread: true,
  },
  {
    id: 3,
    sender: "Quantic OS",
    subject: "Build terminé",
    preview: "La dernière compilation a été terminée avec succès.",
    time: "Hier",
  },
];

const folders = ["Boîte de réception", "Suivis", "Envoyés", "Brouillons", "Archives", "Corbeille"];

export function MailShell() {
  const [selectedId, setSelectedId] = useState(1);
  const [folder, setFolder] = useState("Boîte de réception");
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return mails;
    return mails.filter((mail) =>
      [mail.sender, mail.subject, mail.preview].some((value) => value.toLowerCase().includes(q)),
    );
  }, [query]);

  const selected = mails.find((mail) => mail.id === selectedId) ?? mails[0];

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

        <button className="compose">＋ Nouveau message</button>

        <nav className="folders" aria-label="Dossiers">
          {folders.map((item) => (
            <button
              key={item}
              className={folder === item ? "folder active" : "folder"}
              onClick={() => setFolder(item)}
            >
              <span>{item}</span>
              {item === "Boîte de réception" && <small>2</small>}
            </button>
          ))}
        </nav>

        <div className="account-card">
          <div className="avatar">VH</div>
          <div>
            <strong>Valentin Hernandez</strong>
            <span>valentin.hernandez@sillage.com</span>
          </div>
        </div>
      </aside>

      <section className="mail-list-panel">
        <header className="toolbar">
          <div>
            <span className="eyebrow">QuanticMail</span>
            <h1>{folder}</h1>
          </div>
          <div className="toolbar-actions">
            <button aria-label="Actualiser">↻</button>
            <button aria-label="Réglages">⚙</button>
          </div>
        </header>

        <label className="search">
          <span>⌕</span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Rechercher dans les messages"
          />
        </label>

        <div className="message-list">
          {filtered.map((mail) => (
            <button
              key={mail.id}
              className={selectedId === mail.id ? "message selected" : "message"}
              onClick={() => setSelectedId(mail.id)}
            >
              <div className="message-row">
                <strong>{mail.sender}</strong>
                <time>{mail.time}</time>
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
        <header className="reader-header">
          <div>
            <span className="eyebrow">Message</span>
            <h2>{selected.subject}</h2>
          </div>
          <div className="reader-actions">
            <button>Archiver</button>
            <button>Supprimer</button>
            <button>•••</button>
          </div>
        </header>

        <div className="sender-line">
          <div className="avatar large">QS</div>
          <div>
            <strong>{selected.sender}</strong>
            <span>à valentin.hernandez@sillage.com</span>
          </div>
          <time>{selected.time}</time>
        </div>

        <div className="message-body">
          <p>Bonjour Valentin,</p>
          <p>{selected.preview}</p>
          <p>
            Cette première interface sert de socle au client QuanticMail. Les messages de cette version sont des données locales de démonstration ; la couche JMAP prévue dans le dépôt permettra ensuite de connecter la boîte à un serveur mail réel.
          </p>
          <p>— Quantic Sillage</p>
        </div>

        <div className="reply-box">
          <button>↩ Répondre</button>
          <button>↪ Transférer</button>
        </div>
      </article>
    </main>
  );
}
