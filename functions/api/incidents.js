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

// Common non-name capitalized words to ignore during redaction
const SAFE_WORDS = new Set([
  'I', 'A', 'HR', 'IT', 'OK', 'CEO', 'CTO', 'CFO', 'COO', 'VP', 'PM', 'QA',
  'The', 'This', 'That', 'These', 'Those', 'There', 'Their', 'Then', 'They',
  'What', 'When', 'Where', 'Which', 'While', 'Who', 'Why', 'How',
  'He', 'She', 'His', 'Her', 'Him', 'We', 'Us', 'Our', 'My', 'Me',
  'And', 'But', 'For', 'Not', 'All', 'Any', 'Can', 'Had', 'Has', 'Have',
  'Did', 'Does', 'Was', 'Were', 'Will', 'Would', 'Could', 'Should',
  'May', 'Also', 'Just', 'About', 'After', 'Before', 'Been', 'Being',
  'Some', 'Such', 'Than', 'Too', 'Very', 'Each', 'Every', 'Both',
  'Into', 'Over', 'With', 'From', 'Only', 'Other', 'Because', 'Since',
  'Still', 'Even', 'Here', 'Never', 'Always', 'Sometimes', 'During',
  'If', 'So', 'No', 'Yes', 'Or', 'As', 'At', 'By', 'In', 'Is', 'It',
  'Of', 'On', 'To', 'Up', 'Do', 'An', 'Be', 'Go', 'No',
  'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday',
  'January', 'February', 'March', 'April', 'June', 'July',
  'August', 'September', 'October', 'November', 'December',
  'Podcrash', 'REDACTED', 'Slack', 'Zoom', 'Teams', 'Discord', 'Google',
  'Today', 'Yesterday', 'Tomorrow', 'Morning', 'Afternoon', 'Evening',
  'Meeting', 'Office', 'Team', 'Report', 'Incident', 'Please', 'Thanks',
  'Sorry', 'Hello', 'Hey', 'Dear', 'Note', 'Update', 'However', 'Although',
  'Furthermore', 'Moreover', 'Therefore', 'Meanwhile', 'Regarding',
  'Someone', 'Everyone', 'Anyone', 'Nobody', 'Somebody', 'Everybody',
  'Something', 'Everything', 'Anything', 'Nothing',
  // Gender-neutral replacement words (so they aren't redacted as names)
  'Them', 'Theirs', 'Themself', 'Themselves',
  'Person', 'People', 'Child', 'Children', 'Parent', 'Sibling',
  'Spouse', 'Partner', 'Monarch', 'Royal', 'Friend', 'Mx',
]);

function redactNames(text) {
  // Match sequences of capitalized words (2+ chars, starting with uppercase)
  // This catches "John", "John Smith", "Mary Jane Watson" etc.
  return text.replace(/\b([A-Z][a-z]{1,}(?:\s+[A-Z][a-z]{1,})*)\b/g, (match) => {
    const words = match.split(/\s+/);
    // If it's multiple capitalized words in a row, very likely a name
    if (words.length >= 2) {
      // Check if ALL words are safe (e.g. "Thursday Morning" shouldn't be redacted)
      const allSafe = words.every(w => SAFE_WORDS.has(w));
      if (allSafe) return match;
      return 'REDACTED';
    }
    // Single capitalized word — only redact if it's not a common safe word
    if (SAFE_WORDS.has(words[0])) return match;
    return 'REDACTED';
  });
}

// Gendered word → gender-neutral replacement
const GENDER_MAP = {
  // Pronouns
  'he': 'they', 'him': 'them', 'his': 'their',
  'she': 'they', 'her': 'their', 'hers': 'theirs',
  'himself': 'themself', 'herself': 'themself',
  // People
  'man': 'person', 'woman': 'person',
  'men': 'people', 'women': 'people',
  'boy': 'child', 'girl': 'child',
  'boys': 'children', 'girls': 'children',
  'guy': 'person', 'guys': 'people',
  'gentleman': 'person', 'lady': 'person',
  'gentlemen': 'people', 'ladies': 'people',
  // Titles
  'mr': 'Mx', 'mrs': 'Mx', 'ms': 'Mx', 'miss': 'Mx',
  'sir': 'friend', 'madam': 'friend',
  // Family
  'father': 'parent', 'mother': 'parent',
  'dad': 'parent', 'mom': 'parent', 'mum': 'parent',
  'son': 'child', 'daughter': 'child',
  'brother': 'sibling', 'sister': 'sibling',
  'husband': 'spouse', 'wife': 'spouse',
  'boyfriend': 'partner', 'girlfriend': 'partner',
  // Royalty
  'king': 'monarch', 'queen': 'monarch',
  'prince': 'royal', 'princess': 'royal',
};

function matchCase(original, replacement) {
  if (original === original.toUpperCase()) return replacement.toUpperCase();
  if (original[0] === original[0].toUpperCase()) {
    return replacement[0].toUpperCase() + replacement.slice(1);
  }
  return replacement;
}

function neutralizeGender(text) {
  const keys = Object.keys(GENDER_MAP).sort((a, b) => b.length - a.length);
  const pattern = new RegExp('\\b(' + keys.join('|') + ')\\b', 'gi');
  return text.replace(pattern, (match) => {
    const replacement = GENDER_MAP[match.toLowerCase()];
    return matchCase(match, replacement);
  });
}

function sanitize(text) {
  // Neutralize gender first, then redact names — this ensures gendered
  // pronouns like "Hers"/"Himself" get converted before name detection runs.
  return redactNames(neutralizeGender(text));
}

// GET /api/incidents - list all incidents (latest first)
export async function onRequestGet(context) {
  const { request, env } = context;

  if (!(await authenticate(request, env))) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const incidents = await getIncidents(env);
  // Sanitize old incidents on read (redact names + gender-neutralize)
  const redacted = incidents.map(inc => ({
    ...inc,
    description: sanitize(inc.description)
  }));
  return Response.json({ incidents: redacted });
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
    description: sanitize(description)
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
