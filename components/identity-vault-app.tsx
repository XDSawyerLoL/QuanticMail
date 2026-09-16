"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useState } from "react";
import { randomToken } from "@/lib/quantic/crypto";
import { getLocalIdentity, saveLocalIdentity, type LocalIdentity } from "@/lib/quantic/local-db";
import { exportIdentityVault, importIdentityVault } from "@/lib/quantic/vault";

function downloadTextFile(filename: string, text: string) {
  const blob = new Blob([text], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function IdentityVaultApp() {
  const router = useRouter();
  const [identity, setIdentity] = useState<LocalIdentity | null>(null);
  const [loading, setLoading] = useState(true);
  const [exportPassword, setExportPassword] = useState("");
  const [exportConfirm, setExportConfirm] = useState("");
  const [restorePassword, setRestorePassword] = useState("");
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        setIdentity(await getLocalIdentity());
      } catch {
        setError("Impossible d’ouvrir le stockage local QuanticMail.");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  async function exportVault(event: FormEvent) {
    event.preventDefault();
    if (!identity) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      if (exportPassword !== exportConfirm) {
        throw new Error("Les deux mots de passe du coffre ne correspondent pas.");
      }
      const vault = await exportIdentityVault(identity, exportPassword);
      const fingerprint = identity.fingerprint ?? "identity";
      downloadTextFile(`${identity.handle}-${fingerprint}.quantic-vault`, vault);
      setNotice("Coffre chiffré créé. Conserve ce fichier et son mot de passe séparément.");
      setExportPassword("");
      setExportConfirm("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export du coffre impossible.");
    } finally {
      setBusy(false);
    }
  }

  async function restoreVault(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      if (identity) {
        throw new Error("Une identité est déjà installée sur cet appareil. La restauration n’écrase jamais une identité existante.");
      }
      if (!restoreFile) throw new Error("Choisissez un fichier .quantic-vault.");
      if (restoreFile.size > 1_000_000) throw new Error("Ce fichier de coffre est anormalement volumineux.");

      const restored = await importIdentityVault(await restoreFile.text(), restorePassword);
      const local: LocalIdentity = {
        ...restored,
        authToken: randomToken(),
      };
      await saveLocalIdentity(local);
      setIdentity(local);
      setNotice(`Identité restaurée : ${local.canonicalAddress}. Retour vers QuanticMail…`);
      window.setTimeout(() => {
        router.push("/");
        router.refresh();
      }, 700);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Restauration impossible.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="qn-onboarding qn-vault-page">
      <section className="qn-card qn-vault-card">
        <div className="qn-vault-head">
          <div>
            <div className="qn-mark">Q</div>
            <p className="qn-kicker">QUANTIC IDENTITY VAULT</p>
            <h1>Sauvegarde ton identité, pas ta boîte.</h1>
            <p className="qn-lead">Le coffre contient les clés privées nécessaires pour récupérer exactement la même identité Quantic sur un autre appareil. Il est chiffré localement avant d’être enregistré.</p>
          </div>
          <Link className="qn-back-link" href="/">← QuanticMail</Link>
        </div>

        {loading ? (
          <p className="qn-footnote">Lecture de l’identité locale…</p>
        ) : identity ? (
          <div className="qn-vault-grid">
            <section className="qn-vault-section">
              <p className="qn-kicker">IDENTITÉ INSTALLÉE</p>
              <h2>{identity.address}</h2>
              <code className="qn-vault-address">{identity.canonicalAddress ?? "Migration cryptographique requise"}</code>
              <p className="qn-footnote">Le fichier exporté contient tes clés privées. Il ne contient pas tes messages et n’est envoyé à aucun serveur Quantic.</p>
            </section>

            <section className="qn-vault-section">
              <p className="qn-kicker">EXPORT CHIFFRÉ</p>
              <h2>Créer un coffre</h2>
              <form className="qn-vault-form" onSubmit={exportVault}>
                <label htmlFor="vault-password">Mot de passe du coffre</label>
                <input id="vault-password" type="password" minLength={10} value={exportPassword} onChange={(e) => setExportPassword(e.target.value)} autoComplete="new-password" required />
                <label htmlFor="vault-confirm">Confirmer</label>
                <input id="vault-confirm" type="password" minLength={10} value={exportConfirm} onChange={(e) => setExportConfirm(e.target.value)} autoComplete="new-password" required />
                <button disabled={busy}>{busy ? "Chiffrement…" : "Exporter mon identité"}</button>
              </form>
            </section>
          </div>
        ) : (
          <div className="qn-vault-grid single">
            <section className="qn-vault-section">
              <p className="qn-kicker">RESTAURATION</p>
              <h2>Récupérer une identité</h2>
              <p className="qn-footnote">Sélectionne ton fichier `.quantic-vault`. Après déchiffrement local, QuanticMail générera un nouveau jeton pour cet appareil et prouvera la propriété de l’identité avec ta clé de signature.</p>
              <form className="qn-vault-form" onSubmit={restoreVault}>
                <label htmlFor="vault-file">Fichier du coffre</label>
                <input id="vault-file" type="file" accept=".quantic-vault,application/json" onChange={(e) => setRestoreFile(e.target.files?.[0] ?? null)} required />
                <label htmlFor="restore-password">Mot de passe du coffre</label>
                <input id="restore-password" type="password" minLength={10} value={restorePassword} onChange={(e) => setRestorePassword(e.target.value)} autoComplete="current-password" required />
                <button disabled={busy}>{busy ? "Déchiffrement…" : "Restaurer mon identité"}</button>
              </form>
            </section>
          </div>
        )}

        {(error || notice) && <p className={error ? "qn-error" : "qn-notice"}>{error || notice}</p>}
        <div className="qn-vault-warning">
          <strong>À retenir</strong>
          <p>Perdre à la fois ce fichier et la clé privée locale rend l’identité canonique irrécupérable. Quantic Sillage ne possède aucune copie permettant de la recréer.</p>
        </div>
      </section>
    </main>
  );
}
