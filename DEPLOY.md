# Put PDF ToolHub online

## Option A - Streamlit Community Cloud (free, easiest)
1. Create a GitHub account and a new repository; upload every file in this folder (app.py, engine.py,
   requirements.txt, packages.txt, fonts/, .streamlit/).
2. Go to share.streamlit.io, sign in with GitHub, click "Create app".
3. Pick your repository, branch `main`, main file `app.py`. In Advanced settings choose Python 3.12.
4. Click Deploy. You get a public URL like https://your-name-pdf-toolhub.streamlit.app
`packages.txt` installs OCR (English, Telugu, Hindi) and Noto fonts on the server automatically.

## Option B - Render / Railway / Fly.io / any Docker host
Push the folder to GitHub, create a "Web Service" from the repo with Runtime = Docker. The Dockerfile reads $PORT.

## Option C - Hugging Face Spaces (free)
Create a Space with SDK = Docker. Add this block at the very top of README.md:
---
title: PDF ToolHub
sdk: docker
app_port: 7860
---
and set the environment variable PORT=7860 in the Space settings.

## Option D - Your own server
docker build -t pdf-toolhub .
docker run -p 80:8501 pdf-toolhub

## Before you go public
- Free tiers have about 1 GB RAM: very large PDFs, OCR and "Maximum" compression may fail. Lower maxUploadSize in
  .streamlit/config.toml if needed.
- Files are processed in memory and not saved, but users upload to YOUR server - say so in a privacy note.
- To restrict access, use Streamlit Cloud's "Viewers" setting or put the app behind a login (Cloudflare Access, etc.).
- Custom domain: Render/Railway support it directly; Streamlit Cloud needs a redirect or reverse proxy.

## Accounts, admin and data (important)
- Accounts are stored in a SQLite file at `data/toolhub.db` (override with the `TOOLHUB_DB` environment variable).
- **First admin:** set `ADMIN_EMAIL` and `ADMIN_PASSWORD` as secrets/environment variables BEFORE the site is public.
  If you don't, the first visitor sees an "administrator setup" screen and could claim the role.
  Locally it's fine to use that setup screen. See `.streamlit/secrets.toml.example`.
- **Persistence:** Streamlit Community Cloud and most free hosts have an ephemeral disk - `data/` is wiped on
  restart or redeploy, so accounts disappear. For real use, mount a persistent volume
  (Docker: `docker run -v pdfdata:/app/data -p 8501:8501 pdf-toolhub`; Render: add a Disk mounted at /app/data)
  or move the database to a hosted service.
- **Forgot password:** with SMTP_* set, users get a 6-digit code by email. Without it, requests appear in
  Admin -> Resets and the admin issues a one-time temporary password.
- Sessions last until the browser tab is refreshed or closed (users sign in again after a refresh).
- Edit About / Terms / Privacy text in Admin -> Content, and set your contact email in Admin -> Settings.
  The default legal texts are templates, not legal advice - have them reviewed before launching publicly.
