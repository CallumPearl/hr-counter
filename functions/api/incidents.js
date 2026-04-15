async function authenticate(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return false;
  const token = auth.slice(7);
  const session = await env.INCIDENTS.get(`session:${token}`);
  return session !== null;
}

async function getIncidents(env) {
  const raw = await env.INCIDENTS.get('incidents_data');
  if (!raw) return [];
  try {
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

async function saveIncidents(env, incidents) {
  await env.INCIDENTS.put('incidents_data', JSON.stringify(incidents));
}

// GET /api/incidents - list all incidents (latest first)
export async function onRequestGet(context) {
  const { request, env } = context;

  if (!(await authenticate(request, env))) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const incidents = await getIncidents(env);
  return Response.json({ incidents });
}

// POST /api/incidents - report a new incident
export async function onRequestPost(context) {
  const { request, env } = context;

  if (!(await authenticate(request, env))) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Invalid request.' }, { status: 400 });
  }

  const description = (body.description || '').trim();
  if (!description) {
    return Response.json({ error: 'Description is required.' }, { status: 400 });
  }

  if (description.length > 2000) {
    return Response.json({ error: 'Description too long (max 2000 chars).' }, { status: 400 });
  }

  const incidents = await getIncidents(env);
  incidents.unshift({
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    description
  });

  await saveIncidents(env, incidents);
  return Response.json({ ok: true });
}

// DELETE /api/incidents - delete an incident (requires ADMIN_PASS)
export async function onRequestDelete(context) {
  const { request, env } = context;

  if (!(await authenticate(request, env))) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Invalid request.' }, { status: 400 });
  }

  const adminPass = env.ADMIN_PASS;
  if (!adminPass) {
    return Response.json({ error: 'Server misconfigured: no admin password set.' }, { status: 500 });
  }

  if (!body.admin_password || body.admin_password !== adminPass) {
    return Response.json({ error: 'Wrong admin password.' }, { status: 403 });
  }

  if (!body.id) {
    return Response.json({ error: 'Incident ID is required.' }, { status: 400 });
  }

  const incidents = await getIncidents(env);
  const idx = incidents.findIndex(inc => inc.id === body.id);
  if (idx === -1) {
    return Response.json({ error: 'Incident not found.' }, { status: 404 });
  }

  incidents.splice(idx, 1);
  await saveIncidents(env, incidents);
  return Response.json({ ok: true });
}
