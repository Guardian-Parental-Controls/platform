# Local development

Guardian provides a shared local development setup for the server, Rust agent, Android agent, and documentation.

## Devcontainer

The recommended development environment is the repository devcontainer. It provides Python 3.12, Rust stable, Java 17, Node 24, the Android SDK/NDK, `cargo-ndk`, and container tooling.

With Docker:

```bash
devcontainer up --workspace-folder .
```

With rootless Podman, expose the host socket and use Podman as the Dev Container CLI backend:

```bash
export DEVCONTAINER_DOCKER_SOCKET="$XDG_RUNTIME_DIR/podman/podman.sock"
devcontainer up --workspace-folder . --docker-path podman
```

Inside the container, `CONTAINER_HOST` points the Podman CLI at the mounted host socket.

Verify the toolchain with:

```bash
./scripts/verify-dev-environment.sh
```

## Local setup

For development without the devcontainer, use:

```bash
./scripts/setup-dev.sh
```

Development tool versions are defined in `scripts/dev-versions.env`.

The server uses a project virtual environment at `server/.venv` with dependencies from `server/requirements-dev.txt`.

## Shared validation commands

Use the repository-owned validation entrypoint for local checks:

```bash
./scripts/ci.sh server
./scripts/ci.sh rust
./scripts/ci.sh android
./scripts/ci.sh docs
./scripts/ci.sh all
```

These commands are intended to provide the same build and validation paths for local development and future CI reuse.

## Server

After setup:

```bash
source .env
cd server
./.venv/bin/python app.py
```

Second terminal:

```bash
source .env
cd server
./.venv/bin/python task_worker.py
```

Default login: **admin** / **admin**. Approve devices at `/admin/devices`.

## Tests

Run the server test suite in parallel:

```bash
source .env
cd server
TESTING=True ./.venv/bin/python -m pytest -q -n auto
```

## Debug agent

```bash
source .env
cd server
./.venv/bin/python debug_agent.py \
  --server-url "ws://127.0.0.1:5000/ws" \
  --agent-version "v0.0.0-dev"
```

Delete `debug-agent.json` to simulate a new device.

## Rust agent

```bash
cargo check --manifest-path agent/Cargo.toml
```

Full Linux enforcement requires TimeKpr-nExT D-Bus on the target machine.

## Android

Build the native Rust library and generate the UniFFI Kotlin bindings first:

```bash
./scripts/android-native-build.sh
```

Then build the debug APK:

```bash
cd android-agent
./gradlew assembleDebug --no-daemon
```

## Docs site

```bash
python3 -m venv .venv-docs
.venv-docs/bin/python -m pip install -r requirements-docs.txt
.venv-docs/bin/mkdocs serve
```

Validate documentation changes with:

```bash
.venv-docs/bin/mkdocs build --strict
```

## Related

* [Contributing](contributing.md)
* [Debug agent](../platforms/debug-agent.md)
