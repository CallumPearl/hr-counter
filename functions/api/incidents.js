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

// Common first names (lowercase) to catch regardless of casing
const KNOWN_NAMES = new Set([
  'abbi', 'abbie', 'abby', 'abigail', 'ada', 'adam', 'adrian', 'aidan', 'aiden',
  'aimee', 'al', 'alan', 'alana', 'albert', 'alec', 'alex', 'alexa', 'alexander',
  'alexandra', 'alexis', 'ali', 'alice', 'alicia', 'alina', 'alison', 'allison',
  'alma', 'alyssa', 'amanda', 'amber', 'amelia', 'amy', 'ana', 'andrea', 'andrew',
  'andy', 'angela', 'angelina', 'angie', 'anita', 'ann', 'anna', 'anne', 'annie',
  'anthony', 'anton', 'antonio', 'april', 'archie', 'aria', 'ariana', 'ariel',
  'arjun', 'arnold', 'arthur', 'ash', 'ashlee', 'ashley', 'ashton', 'audrey',
  'austin', 'autumn', 'ava', 'avery', 'axel',
  'bailey', 'barbara', 'barry', 'beau', 'becky', 'bella', 'ben', 'benjamin',
  'bernard', 'beth', 'bethany', 'betty', 'beverly', 'bill', 'billy', 'blake',
  'bob', 'bobby', 'bonnie', 'brad', 'bradley', 'brandon', 'brenda', 'brendan',
  'brent', 'brett', 'brian', 'briana', 'brianna', 'bridget', 'brittany', 'brock',
  'brooke', 'brooklyn', 'bruce', 'bruno', 'bryan', 'bryce',
  'caitlin', 'caleb', 'callum', 'calvin', 'cameron', 'camila', 'carl', 'carla',
  'carlos', 'carmen', 'carol', 'carolina', 'caroline', 'carolyn', 'carrie',
  'carter', 'casey', 'cassandra', 'cassidy', 'catherine', 'cecilia', 'chad',
  'charles', 'charlie', 'charlotte', 'chase', 'chelsea', 'cheryl', 'chloe',
  'chris', 'christian', 'christina', 'christine', 'christopher', 'chuck', 'cindy',
  'claire', 'clara', 'clarence', 'clark', 'claude', 'claudia', 'clay', 'cliff',
  'clifford', 'clint', 'clyde', 'cody', 'cole', 'colin', 'colleen', 'collin',
  'connor', 'cooper', 'cora', 'corey', 'cory', 'courtney', 'craig', 'crystal',
  'curtis', 'cynthia',
  'daisy', 'dakota', 'dale', 'damian', 'damon', 'dan', 'dana', 'daniel',
  'daniela', 'danielle', 'danny', 'daphne', 'darcy', 'darlene', 'darren',
  'daryl', 'dave', 'david', 'dawn', 'dean', 'deanna', 'debbie', 'deborah',
  'debra', 'declan', 'deidre', 'delia', 'delilah', 'denis', 'denise', 'dennis',
  'derek', 'desiree', 'destiny', 'devin', 'devon', 'diana', 'diane', 'diego',
  'dillon', 'dolly', 'dominic', 'don', 'donald', 'donna', 'doris', 'dorothy',
  'doug', 'douglas', 'drew', 'duncan', 'dustin', 'dwight', 'dylan',
  'earl', 'ed', 'eddie', 'eden', 'edgar', 'edith', 'edna', 'edward', 'edwin',
  'eileen', 'elaine', 'eleanor', 'elena', 'eli', 'eliana', 'elijah', 'elise',
  'elizabeth', 'ella', 'ellen', 'ellie', 'elliot', 'elliott', 'eloise', 'elsa',
  'elsie', 'emery', 'emilia', 'emily', 'emma', 'emmett', 'eric', 'erica', 'erik',
  'erika', 'erin', 'ernest', 'esme', 'esther', 'ethan', 'eugene', 'eva',
  'evelyn', 'everett', 'evie', 'ezra',
  'faith', 'fatima', 'faye', 'felicia', 'felix', 'fern', 'fernando', 'finley',
  'finn', 'fiona', 'fletcher', 'flora', 'florence', 'floyd', 'frances', 'francis',
  'frank', 'frankie', 'franklin', 'fred', 'freddie', 'frederick',
  'gabe', 'gabriel', 'gabriella', 'gabrielle', 'gail', 'garrett', 'gary', 'gavin',
  'gemma', 'gene', 'genevieve', 'george', 'gerald', 'geraldine', 'gina', 'glen',
  'glenn', 'gloria', 'gordon', 'grace', 'gracie', 'graham', 'grant', 'greg',
  'gregg', 'gregory', 'greta', 'griffin', 'gus',
  'hadley', 'hailey', 'haley', 'hank', 'hannah', 'harley', 'harold', 'harper',
  'harriet', 'harrison', 'harry', 'harvey', 'hayden', 'hayley', 'hazel', 'heath',
  'heather', 'heidi', 'helen', 'helena', 'henry', 'herbert', 'holly', 'hope',
  'howard', 'hudson', 'hugh', 'hugo', 'hunter',
  'ian', 'ibrahim', 'ida', 'imogen', 'ines', 'ira', 'irene', 'iris', 'irving',
  'isaac', 'isabel', 'isabella', 'isabelle', 'isaiah', 'isla', 'ivan', 'ivy',
  'jack', 'jackson', 'jacob', 'jacqueline', 'jade', 'jake', 'james', 'jamie',
  'jan', 'jane', 'janet', 'janice', 'jared', 'jasmine', 'jason', 'jasper',
  'javier', 'jay', 'jayden', 'jean', 'jeanette', 'jeff', 'jeffery', 'jeffrey',
  'jen', 'jenna', 'jennifer', 'jenny', 'jeremiah', 'jeremy', 'jerome', 'jerry',
  'jess', 'jesse', 'jessica', 'jessie', 'jill', 'jim', 'jimmy', 'jo', 'joan',
  'joanna', 'joanne', 'jocelyn', 'jodi', 'jody', 'joe', 'joel', 'joey', 'john',
  'johnathan', 'johnny', 'jon', 'jonathan', 'jonah', 'jordan', 'jorge', 'jose',
  'joseph', 'josephine', 'josh', 'joshua', 'josie', 'joy', 'joyce', 'juan',
  'judith', 'judy', 'julia', 'julian', 'juliana', 'julie', 'juliet', 'june',
  'justin', 'justine',
  'kai', 'kaitlyn', 'kara', 'karen', 'kari', 'karl', 'kate', 'katelyn',
  'katherine', 'kathleen', 'kathryn', 'kathy', 'katie', 'katrina', 'kay',
  'kayla', 'kaylee', 'keegan', 'keith', 'kelley', 'kelli', 'kelly', 'kelsey',
  'ken', 'kendra', 'kendrick', 'kenneth', 'kenny', 'kent', 'kerry', 'kevin',
  'khloe', 'kiana', 'kiera', 'kim', 'kimberly', 'kirk', 'kit', 'krista',
  'kristen', 'kristin', 'kristina', 'kristy', 'kurt', 'kyle', 'kylie', 'kyra',
  'lacey', 'laila', 'lance', 'landon', 'lane', 'lara', 'larry', 'laura',
  'lauren', 'laurie', 'laverne', 'lawrence', 'layla', 'lea', 'leah', 'lee',
  'leigh', 'lena', 'leo', 'leon', 'leonard', 'leroy', 'leslie', 'levi', 'lewis',
  'lexi', 'liam', 'lila', 'lillian', 'lily', 'lincoln', 'linda', 'lindsay',
  'lindsey', 'lisa', 'liv', 'logan', 'lois', 'lola', 'lorena', 'lorraine',
  'louie', 'louis', 'louise', 'luca', 'lucas', 'lucia', 'lucille', 'lucy',
  'luis', 'luke', 'luna', 'lydia', 'lynda', 'lynn', 'lynne',
  'mabel', 'mack', 'mackenzie', 'macy', 'maddie', 'maddox', 'madeline',
  'madison', 'mae', 'maggie', 'malik', 'mallory', 'mandy', 'manuel', 'marc',
  'marcella', 'marcia', 'marco', 'marcus', 'margaret', 'maria', 'mariah',
  'marian', 'marie', 'marilyn', 'marina', 'mario', 'marion', 'marissa', 'mark',
  'marlene', 'marsha', 'marshall', 'martha', 'martin', 'marty', 'marvin', 'mary',
  'mason', 'mateo', 'mathew', 'matt', 'matthew', 'maureen', 'max', 'maxine',
  'maxwell', 'maya', 'megan', 'melanie', 'melissa', 'melody', 'mercedes',
  'meredith', 'mia', 'micah', 'michael', 'michele', 'michelle', 'mickey', 'miguel',
  'mike', 'mila', 'miles', 'millie', 'milo', 'mindy', 'miranda', 'miriam',
  'mitchell', 'mohammed', 'molly', 'mona', 'monica', 'monique', 'morgan', 'morris',
  'murphy', 'myles', 'myra', 'myrtle',
  'nadia', 'nancy', 'naomi', 'natalie', 'natasha', 'nate', 'nathan', 'nathaniel',
  'ned', 'neil', 'nell', 'nelson', 'neville', 'nicholas', 'nick', 'nicki',
  'nicole', 'nigel', 'nikki', 'nina', 'noah', 'noel', 'noelle', 'nolan', 'nora',
  'norma', 'norman',
  'oliver', 'olivia', 'omar', 'opal', 'oscar', 'otto', 'owen',
  'paige', 'pam', 'pamela', 'parker', 'pat', 'patricia', 'patrick', 'patty',
  'paul', 'paula', 'pauline', 'pearl', 'pedro', 'peggy', 'penny', 'percy',
  'perry', 'pete', 'peter', 'peyton', 'phil', 'philip', 'phillip', 'phoebe',
  'phyllis', 'pierce', 'piper', 'polly', 'porter', 'preston', 'priscilla',
  'quinn',
  'rachel', 'rafael', 'ralph', 'ramona', 'randall', 'randy', 'raquel', 'ray',
  'raymond', 'reagan', 'rebecca', 'reed', 'reese', 'regan', 'regina', 'reid',
  'remy', 'renee', 'rex', 'rhonda', 'ricardo', 'richard', 'rick', 'ricky',
  'riley', 'rita', 'rob', 'robbie', 'robert', 'roberta', 'robin', 'rocco', 'rod',
  'rodney', 'roger', 'roland', 'roman', 'ron', 'ronald', 'ronnie', 'rosa',
  'rosalie', 'rose', 'rosemary', 'rosie', 'ross', 'rowan', 'roxanne', 'roy',
  'ruby', 'russ', 'russell', 'ruth', 'ryan',
  'sabrina', 'sadie', 'sally', 'sam', 'samantha', 'samuel', 'sandra', 'sandy',
  'santiago', 'sara', 'sarah', 'savannah', 'sawyer', 'scarlett', 'scott', 'sean',
  'sebastian', 'selena', 'serena', 'seth', 'shane', 'shannon', 'shari', 'sharon',
  'shaun', 'shawn', 'shawna', 'sheila', 'shelby', 'sheldon', 'shelly', 'sheri',
  'sherri', 'sherry', 'shirley', 'sidney', 'sierra', 'silas', 'silvia', 'simon',
  'simone', 'skyler', 'sofia', 'sonia', 'sonya', 'sophia', 'sophie', 'spencer',
  'stacey', 'stacy', 'stan', 'stanley', 'stella', 'stephanie', 'stephen', 'steve',
  'steven', 'stuart', 'sue', 'summer', 'susan', 'susie', 'suzanne', 'sven',
  'sydney', 'sylvia',
  'tabitha', 'tamara', 'tammy', 'tanya', 'tara', 'taryn', 'tasha', 'taylor',
  'ted', 'teddy', 'teresa', 'terrance', 'terrence', 'terri', 'terry', 'tessa',
  'theo', 'theodore', 'theresa', 'thomas', 'tiffany', 'tim', 'timothy', 'tina',
  'tobias', 'toby', 'todd', 'tom', 'tommy', 'tony', 'tonya', 'tori', 'tracey',
  'tracy', 'travis', 'trent', 'trevor', 'trey', 'tricia', 'trina', 'trish',
  'tristan', 'troy', 'tucker', 'tyler',
  'ulysses', 'ursula',
  'val', 'valerie', 'vanessa', 'vera', 'vernon', 'veronica', 'vicki', 'vicky',
  'victor', 'victoria', 'vince', 'vincent', 'viola', 'violet', 'virginia',
  'vivian', 'vivienne',
  'wade', 'walker', 'wallace', 'walt', 'walter', 'wanda', 'warren', 'wayne',
  'wendell', 'wendy', 'wes', 'wesley', 'whitney', 'wilbur', 'will', 'william',
  'willie', 'willow', 'wilma', 'wilson', 'winnie', 'winston', 'wyatt',
  'xander', 'xavier',
  'yolanda', 'yusuf', 'yvette', 'yvonne',
  'zach', 'zachary', 'zack', 'zane', 'zara', 'zelda', 'zoe', 'zoey',
]);

function redactNames(text) {
  // Pass 1: catch known names in any casing (case-insensitive)
  const namePattern = new RegExp(
    '\\b(' + Array.from(KNOWN_NAMES).sort((a, b) => b.length - a.length).join('|') + ')\\b',
    'gi'
  );
  text = text.replace(namePattern, 'REDACTED');

  // Pass 2: catch remaining capitalized words that look like names
  return text.replace(/\b([A-Z][a-z]{1,}(?:\s+[A-Z][a-z]{1,})*)\b/g, (match) => {
    const words = match.split(/\s+/);
    if (words.length >= 2) {
      const allSafe = words.every(w => SAFE_WORDS.has(w));
      if (allSafe) return match;
      return 'REDACTED';
    }
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
