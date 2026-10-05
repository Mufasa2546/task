# Task

Your personal command center: daily goals with reminders, an activity log, your businesses, your apps and websites, and an AI assistant.

- Works offline once opened (service worker), and installs to your phone's home screen.
- Sends notifications when a goal is due.
- Data stays on your device. The AI assistant uses your own Anthropic API key, entered in the app.

## Editing

Edit `src/app.html`, then run `sh build.sh` to regenerate `index.html`. The site is served by GitHub Pages from the `main` branch root.

## Accounts and sync

`worker/index.js` is a Cloudflare Worker that serves the app (Workers Assets) and handles `/api/*`:
sign up, sign in, team invite codes and item sync. Data lives in one SQLite-backed Durable Object (`Store`),
so no database needs creating in the Cloudflare dashboard. Brandbridge items (clients and deals, projects,
goals for the partner or both, Brandbridge log entries, anything marked "Share") sync to the team; everything
else syncs only to the signed-in person's own devices. Without the API (GitHub Pages copy, claude.ai) the app runs offline-only.
