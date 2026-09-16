import { NextResponse } from 'next/server';
import { Resend } from 'resend';

export const runtime = 'nodejs';

function getResendClient() {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    throw new Error('RESEND_API_KEY is not configured');
  }
  return new Resend(apiKey);
}

export async function GET() {
  return NextResponse.json({
    ok: true,
    service: 'QuanticMail inbound gateway',
    provider: 'Resend',
    configured: Boolean(process.env.RESEND_API_KEY && process.env.RESEND_WEBHOOK_SECRET),
  });
}

export async function POST(request: Request) {
  try {
    const webhookSecret = process.env.RESEND_WEBHOOK_SECRET;
    if (!webhookSecret) {
      console.error('QuanticMail inbound webhook is missing RESEND_WEBHOOK_SECRET');
      return new NextResponse('Inbound gateway not configured', { status: 503 });
    }

    const id = request.headers.get('svix-id');
    const timestamp = request.headers.get('svix-timestamp');
    const signature = request.headers.get('svix-signature');

    if (!id || !timestamp || !signature) {
      return new NextResponse('Missing webhook signature headers', { status: 400 });
    }

    const payload = await request.text();
    const resend = getResendClient();

    const event = resend.webhooks.verify({
      payload,
      headers: { id, timestamp, signature },
      webhookSecret,
    });

    if (event.type !== 'email.received') {
      return NextResponse.json({ ok: true, ignored: event.type });
    }

    const received = await resend.emails.receiving.get(event.data.email_id);
    if (received.error || !received.data) {
      console.error('Unable to retrieve inbound email', {
        emailId: event.data.email_id,
        error: received.error,
      });
      return new NextResponse('Unable to retrieve inbound email', { status: 502 });
    }

    const email = received.data;

    // V0.4 intentionally does not persist mailbox contents on Render.
    // Resend remains the temporary ingress queue until the QuanticMail Node
    // running on the user's PC pulls the message into local storage.
    console.info('QuanticMail inbound email received', {
      emailId: event.data.email_id,
      from: email.from,
      to: email.to,
      subject: email.subject,
      hasHtml: Boolean(email.html),
      hasText: Boolean(email.text),
    });

    return NextResponse.json({
      ok: true,
      emailId: event.data.email_id,
      delivery: 'accepted-for-local-node',
    });
  } catch (error) {
    console.error('Invalid or failed Resend inbound webhook', error);
    return new NextResponse('Invalid webhook', { status: 400 });
  }
}
