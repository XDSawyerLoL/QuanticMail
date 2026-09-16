"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";

export function LoginForm({ initialError }: { initialError?: string }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(initialError || "");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");

    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = (await response.json()) as { error?: string };
      if (!response.ok) {
        setError(data.error || "Connexion impossible.");
        return;
      }
      setPassword("");
      router.refresh();
    } catch {
      setError("Impossible de joindre QuanticMail.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-page">
      <section className="login-card">
        <div className="brand login-brand">
          <div className="brand-mark" aria-hidden="true">Q</div>
          <div>
            <strong>QuanticMail</strong>
            <span>by Quantic Sillage</span>
          </div>
        </div>

        <div className="login-copy">
          <span className="eyebrow">Messagerie sécurisée</span>
          <h1>Connexion</h1>
          <p>Connectez-vous avec votre adresse QuanticMail. Les identifiants sont utilisés uniquement côté serveur pour ouvrir votre session JMAP.</p>
        </div>

        <form className="login-form" onSubmit={submit}>
          <label>
            Adresse email
            <input
              type="email"
              autoComplete="username"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="prenom.nom@sillage.com"
              required
            />
          </label>
          <label>
            Mot de passe
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </label>
          {error && <p className="form-error" role="alert">{error}</p>}
          <button type="submit" disabled={busy}>{busy ? "Connexion…" : "Se connecter"}</button>
        </form>
      </section>
    </main>
  );
}
