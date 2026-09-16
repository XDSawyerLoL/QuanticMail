import { JMAP_CORE, JMAP_MAIL, JmapClient } from "@/lib/mail/jmap";
import type { MailSession } from "@/lib/auth/session";

export type MailboxItem = {
  id: string;
  name: string;
  role: string | null;
  totalEmails: number;
  unreadEmails: number;
};

export type MailItem = {
  id: string;
  sender: string;
  senderEmail: string;
  subject: string;
  preview: string;
  receivedAt: string;
  unread: boolean;
  starred: boolean;
  body: string;
};

export type MailSnapshot = {
  accountEmail: string;
  activeMailboxId: string | null;
  mailboxes: MailboxItem[];
  messages: MailItem[];
};

type MethodResponse<T> = [string, T, string];

type MailboxGetResponse = {
  list: Array<{
    id: string;
    name: string;
    role?: string | null;
    totalEmails?: number;
    unreadEmails?: number;
  }>;
};

type EmailQueryResponse = { ids: string[] };

type EmailGetResponse = {
  list: Array<{
    id: string;
    from?: Array<{ name?: string; email: string }>;
    subject?: string;
    preview?: string;
    receivedAt?: string;
    keywords?: Record<string, boolean>;
    textBody?: Array<{ partId: string }>;
    htmlBody?: Array<{ partId: string }>;
    bodyValues?: Record<string, { value?: string }>;
  }>;
};

type IdentityGetResponse = {
  list: Array<{ id: string; email: string; name?: string }>;
};

type EmailSetResponse = {
  created?: Record<string, { id: string }>;
  notCreated?: Record<string, { type: string; description?: string }>;
};

function sessionUrl() {
  const value = process.env.JMAP_SESSION_URL;
  if (!value) throw new Error("JMAP_SESSION_URL is not configured");
  return value;
}

function accountId(session: Awaited<ReturnType<typeof JmapClient.discover>>) {
  const id = session.primaryAccounts[JMAP_MAIL];
  if (!id) throw new Error("No primary JMAP mail account is available");
  return id;
}

function responseAt<T>(responses: unknown[], index: number) {
  const entry = responses[index] as MethodResponse<T> | undefined;
  if (!entry || entry[0] === "error") throw new Error("JMAP returned a method error");
  return entry[1];
}

function textBody(message: EmailGetResponse["list"][number]) {
  const textPart = message.textBody?.[0]?.partId;
  const htmlPart = message.htmlBody?.[0]?.partId;
  const partId = textPart ?? htmlPart;
  const value = partId ? message.bodyValues?.[partId]?.value : undefined;
  return value ?? message.preview ?? "";
}

export async function validateMailbox(authorization: string) {
  const discovered = await JmapClient.discover(sessionUrl(), authorization);
  accountId(discovered);
  return discovered;
}

export async function getMailSnapshot(
  auth: MailSession,
  requestedMailboxId?: string,
): Promise<MailSnapshot> {
  const discovered = await JmapClient.discover(sessionUrl(), auth.authorization);
  const id = accountId(discovered);
  const client = new JmapClient(discovered, auth.authorization);

  const mailboxResponse = await client.call(
    [["Mailbox/get", { accountId: id, ids: null }, "mailboxes"]],
    [JMAP_CORE, JMAP_MAIL],
  );
  const mailboxData = responseAt<MailboxGetResponse>(mailboxResponse.methodResponses, 0);
  const requested = requestedMailboxId
    ? mailboxData.list.find((item) => item.id === requestedMailboxId)
    : undefined;
  const activeMailbox = requested ?? mailboxData.list.find((item) => item.role === "inbox") ?? mailboxData.list[0];

  if (!activeMailbox) {
    return { accountEmail: auth.email, activeMailboxId: null, mailboxes: [], messages: [] };
  }

  const queryResponse = await client.call(
    [[
      "Email/query",
      {
        accountId: id,
        filter: { inMailbox: activeMailbox.id },
        sort: [{ property: "receivedAt", isAscending: false }],
        limit: 50,
      },
      "query",
    ]],
    [JMAP_CORE, JMAP_MAIL],
  );
  const query = responseAt<EmailQueryResponse>(queryResponse.methodResponses, 0);

  let messages: MailItem[] = [];
  if (query.ids.length) {
    const emailResponse = await client.call(
      [[
        "Email/get",
        {
          accountId: id,
          ids: query.ids,
          properties: [
            "id",
            "from",
            "subject",
            "preview",
            "receivedAt",
            "keywords",
            "textBody",
            "htmlBody",
            "bodyValues",
          ],
          fetchTextBodyValues: true,
          fetchHTMLBodyValues: true,
          maxBodyValueBytes: 200000,
        },
        "emails",
      ]],
      [JMAP_CORE, JMAP_MAIL],
    );
    const emails = responseAt<EmailGetResponse>(emailResponse.methodResponses, 0);
    messages = emails.list.map((message) => ({
      id: message.id,
      sender: message.from?.[0]?.name || message.from?.[0]?.email || "Expéditeur inconnu",
      senderEmail: message.from?.[0]?.email || "",
      subject: message.subject || "(Sans objet)",
      preview: message.preview || "",
      receivedAt: message.receivedAt || "",
      unread: !message.keywords?.["$seen"],
      starred: Boolean(message.keywords?.["$flagged"]),
      body: textBody(message),
    }));
  }

  return {
    accountEmail: auth.email,
    activeMailboxId: activeMailbox.id,
    mailboxes: mailboxData.list.map((mailbox) => ({
      id: mailbox.id,
      name: mailbox.name,
      role: mailbox.role ?? null,
      totalEmails: mailbox.totalEmails ?? 0,
      unreadEmails: mailbox.unreadEmails ?? 0,
    })),
    messages,
  };
}

export async function sendMessage(
  auth: MailSession,
  input: { to: string; subject: string; body: string },
) {
  const discovered = await JmapClient.discover(sessionUrl(), auth.authorization);
  const id = accountId(discovered);
  const client = new JmapClient(discovered, auth.authorization);

  const meta = await client.call(
    [
      ["Mailbox/get", { accountId: id, ids: null }, "mailboxes"],
      ["Identity/get", { accountId: id, ids: null }, "identities"],
    ],
    [JMAP_CORE, JMAP_MAIL, "urn:ietf:params:jmap:submission"],
  );

  const mailboxes = responseAt<MailboxGetResponse>(meta.methodResponses, 0).list;
  const identities = responseAt<IdentityGetResponse>(meta.methodResponses, 1).list;
  const identity = identities.find((item) => item.email.toLowerCase() === auth.email.toLowerCase()) ?? identities[0];
  const drafts = mailboxes.find((item) => item.role === "drafts");
  const sent = mailboxes.find((item) => item.role === "sent");

  if (!identity) throw new Error("No JMAP sending identity is available");
  if (!drafts) throw new Error("No drafts mailbox is available");

  const create = await client.call(
    [[
      "Email/set",
      {
        accountId: id,
        create: {
          draft: {
            mailboxIds: { [drafts.id]: true },
            keywords: { "$seen": true, "$draft": true },
            from: [{ name: identity.name || "", email: identity.email }],
            to: [{ email: input.to }],
            subject: input.subject,
            bodyStructure: { type: "text/plain", partId: "body" },
            bodyValues: { body: { value: input.body } },
          },
        },
      },
      "create",
    ]],
    [JMAP_CORE, JMAP_MAIL],
  );

  const created = responseAt<EmailSetResponse>(create.methodResponses, 0);
  const emailId = created.created?.draft?.id;
  if (!emailId) {
    const reason = created.notCreated?.draft?.description || created.notCreated?.draft?.type;
    throw new Error(reason || "JMAP could not create the draft");
  }

  const updateEmail: Record<string, unknown> = {
    "keywords/$draft": null,
    [`mailboxIds/${drafts.id}`]: null,
  };
  if (sent) updateEmail[`mailboxIds/${sent.id}`] = true;

  const submission = await client.call(
    [[
      "EmailSubmission/set",
      {
        accountId: id,
        create: {
          send: {
            identityId: identity.id,
            emailId,
          },
        },
        onSuccessUpdateEmail: { "#send": updateEmail },
      },
      "submit",
    ]],
    [JMAP_CORE, JMAP_MAIL, "urn:ietf:params:jmap:submission"],
  );

  const result = submission.methodResponses[0] as MethodResponse<{
    created?: Record<string, { id: string }>;
    notCreated?: Record<string, { type: string; description?: string }>;
  }>;
  const submissionId = result?.[1]?.created?.send?.id;
  if (!submissionId) {
    const failure = result?.[1]?.notCreated?.send;
    throw new Error(failure?.description || failure?.type || "JMAP submission failed");
  }

  return { emailId, submissionId };
}
