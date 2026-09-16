import { LoginForm } from "@/components/login-form";
import { MailShell } from "@/components/mail-shell";
import { readSession } from "@/lib/auth/session";
import { getMailSnapshot } from "@/lib/mail/service";

export default async function Home() {
  const session = await readSession();
  if (!session) return <LoginForm />;

  try {
    const snapshot = await getMailSnapshot(session);
    return <MailShell initialSnapshot={snapshot} />;
  } catch {
    return <LoginForm initialError="Impossible d’ouvrir la boîte. Vérifiez la configuration JMAP puis reconnectez-vous." />;
  }
}
