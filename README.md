# Quantum Hub

Workspace web app with React + TypeScript, FastAPI and PostgreSQL.

## Features
- Account registration and login with hashed passwords and signed sessions
- Personal dashboard and metrics
- Project CRUD
- Task CRUD with status and priority
- Notes CRUD
- Profile editing
- Admin-only user list and account activation controls
- Responsive dark/light interface

## Run locally
Requires Docker, or Python 3.12 and Node 22.

```bash
docker build -t quantum-hub .
docker run --rm -p 10000:10000 -e JWT_SECRET="change-this-secret" quantum-hub
```

For local development without PostgreSQL, the API falls back to SQLite. Set `DATABASE_URL` for PostgreSQL in production.

## Render
The root `render.yaml` defines a Docker web service and a PostgreSQL database. The first account created is the initial administrator unless `ADMIN_EMAIL` and `ADMIN_PASSWORD` are supplied in Render. Set those two variables before exposing the app publicly if you want a pre-created admin account.

Never commit credentials or secret values. The Render Blueprint generates `JWT_SECRET`.
