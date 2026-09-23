# Deploying Pause API

Pause API is a stateless Node 22 service. It listens on `PORT` (default `3000`) and exposes:

- `GET /health/live` — process liveness
- `GET /health/ready` — deployment readiness
- `POST /v1/analyses` — the mobile analysis contract

## Container deployment

Build and run the included container locally:

```bash
docker build -t pause-api .
docker run --rm -p 3000:3000 --env-file .env pause-api
```

For a host such as Fly, Render, Railway, Cloud Run, or ECS, build from the included `Dockerfile`, expose port `3000` (or provide `PORT`), and configure the readiness probe as `/health/ready`.

## Required production configuration

Start from `.env.example`. Production must run behind HTTPS. Do not place `CORS_ORIGIN` unless a browser client needs it; iOS and Android clients do not require CORS.

Rate limiting is per process for this MVP. At multi-instance scale, enforce equivalent rate limits at the hosting edge or move the rate-limit store to Redis.

## Optional live URL reputation

Set `WEB_RISK_API_KEY` to enable Google Web Risk Lookup API enrichment for every submitted URL. The service sends each submitted URL to Google only when this option is enabled; do not enable it until that disclosure is reflected in Pause's user-facing privacy policy. A provider timeout never changes a result to “safe.”

Set `TYPESAFE_API_KEY` to enable bounded TypeSafe SystemOne message decisioning. Pause redacts six-digit codes and card-like values before sending text to this provider; its findings add evidence but never overrule deterministic domain/reputation evidence or create a “safe” verdict.

## Connecting a release candidate

Use your HTTPS origin, without a trailing `/v1` path:

```bash
cd ../pause_mobile
make run-hosted API_URL=https://api.your-domain.example
```

The mobile app refuses non-HTTPS endpoints other than its localhost development default.
