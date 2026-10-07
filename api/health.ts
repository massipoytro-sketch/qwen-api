export default function handler() {
  return new Response(JSON.stringify({
    service: "gainiren-security",
    status: "ok",
    version: "0.1",
  }), {
    status: 200,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}
