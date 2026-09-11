# Guardian platform

[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://guardian-parental-controls.github.io/docs/)

Guardian is a multi-tenant parental-control server. This repository contains
the Flask web application, WebSocket hub, background worker, browser extension,
and container packaging.

## Related repositories

- [agent-common](https://github.com/Guardian-Parental-Controls/agent-common) —
  shared protocol and policy logic
- [agent-linux](https://github.com/Guardian-Parental-Controls/agent-linux)
- [agent-windows](https://github.com/Guardian-Parental-Controls/agent-windows)
- [agent-android](https://github.com/Guardian-Parental-Controls/agent-android)
- [docs](https://github.com/Guardian-Parental-Controls/docs)
- [translations](https://github.com/Guardian-Parental-Controls/translations)
- [versions](https://github.com/Guardian-Parental-Controls/versions) — compiled
  release feed

## Quick start

```bash
cp .env.example .env
docker compose up -d
```

Sign in at the dashboard with **admin** / **admin**, then change the password
under **Settings**.

## Development

```bash
./scripts/setup-dev.sh
cd server
TESTING=True ./.venv/bin/python -m pytest -q -n auto
```

UI strings are maintained in the translations repository. Product pull
requests which add keys must link the translations pull request:

```text
Translations: #42
```

## Version 1.0

Version 1.0 is a breaking repository and release-system change. Agent versions,
repositories, and artifact URLs come only from the
[compiled versions feed](https://guardian-parental-controls.github.io/versions/feed.json).
See the [migration guide](https://guardian-parental-controls.github.io/docs/latest/getting-started/v1-migration/).

## License

MIT — see `LICENSE`.
