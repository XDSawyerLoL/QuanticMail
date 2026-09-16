export type JmapSession = {
  apiUrl: string;
  downloadUrl: string;
  uploadUrl: string;
  eventSourceUrl?: string;
  accounts: Record<string, { name: string; isPersonal: boolean; isReadOnly: boolean }>;
  primaryAccounts: Record<string, string>;
  capabilities: Record<string, unknown>;
};

export type JmapMethodCall = [string, Record<string, unknown>, string];

export class JmapClient {
  constructor(
    private readonly session: JmapSession,
    private readonly authorization: string,
  ) {}

  static async discover(sessionUrl: string, authorization: string) {
    const response = await fetch(sessionUrl, {
      headers: { Authorization: authorization },
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error(`JMAP session discovery failed (${response.status})`);
    }

    return (await response.json()) as JmapSession;
  }

  async call(methodCalls: JmapMethodCall[], using: string[]) {
    const response = await fetch(this.session.apiUrl, {
      method: "POST",
      headers: {
        Authorization: this.authorization,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ using, methodCalls }),
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error(`JMAP request failed (${response.status})`);
    }

    return response.json() as Promise<{
      methodResponses: unknown[];
      sessionState: string;
    }>;
  }
}

export const JMAP_CORE = "urn:ietf:params:jmap:core";
export const JMAP_MAIL = "urn:ietf:params:jmap:mail";
