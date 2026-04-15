export async function onRequestPost(context) {
  const { request, env } = context;

  const password = env.PASSWORD;
  if (!password) {
    return Response.json({ error: 'Server misconfigured: no password set.' }, { status: 500 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Invalid request.' }, { status: 400 });
  }

  if (!body.password || body.password !== password) {
    return Response.json({ error: 'Wrong password.' }, { status: 401 });
  }

  // Generate a simple session token (hash of password + timestamp + random)
  const tokenData = new TextEncoder().encode(password + Date.now() + Math.random());
  const hashBuffer = await crypto.subtle.digest('SHA-256', tokenData);
  const token = Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  // Store token in KV with 24h TTL
  await env.INCIDENTS.put(`session:${token}`, '1', { expirationTtl: 86400 });

  return Response.json({ token });
}
