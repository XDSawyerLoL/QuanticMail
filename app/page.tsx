import { LoginForm } from "@/components/login-form";
import { MailShell } from "@/components/mail-shell";
import { readSession } from "@/lib/auth/session";
import { getMailSnapshot, type MailSnapshot } from "@/lib/mail/service";

export default async function Home() {
  const session = await readSession();
  if (!session) return <LoginForm />;

  let snapshot: MailSnapshot;
  try {
    snapshot = await getMailSnapshot(session);
  } catch {
    return <LoginForm initialError="Impossible d’ouvrir la boîte. Vérifiez la configuration JMAP puis reconnectez-vous." />;
  }

  return <MailShell initialSnapshot={snapshot} />;
}
