export async function GET() {
  return Response.json({
    ok: true,
    protocol: "quantic-relay/1",
    service: "Quantic Network Relay",
    time: new Date().toISOString(),
  });
}
