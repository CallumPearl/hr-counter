# Podcrash HR Incident Tracker

A Cloudflare Pages site that tracks how long it's been since the last HR incident at Podcrash.

## Features

- Live timer counting up in days, hours, minutes, seconds since last incident
- Report button that opens a dialog to describe what happened
- Incident log displayed below timer, latest to oldest
- Time gaps between incidents shown in the log
- Counter resets every time a new incident is reported
- Password protected via environment variable

## Setup

### 1. Create a KV Namespace

```bash
npx wrangler kv:namespace create "INCIDENTS"
```

Copy the `id` from the output and replace `REPLACE_WITH_KV_NAMESPACE_ID` in `wrangler.toml`.

### 2. Set the PASSWORD environment variable

In the Cloudflare Pages dashboard:

1. Go to your project > Settings > Environment variables
2. Add a variable named `PASSWORD` with your desired password
3. Mark it as encrypted/secret

Or via wrangler:

```bash
npx wrangler pages secret put PASSWORD
```

### 3. Deploy

```bash
npx wrangler pages deploy public
```

### 4. Bind KV to Pages

In the Cloudflare dashboard:

1. Go to your Pages project > Settings > Functions > KV namespace bindings
2. Add binding: Variable name = `INCIDENTS`, KV namespace = the one you created

## Local Development

```bash
npx wrangler pages dev public --kv INCIDENTS
```
