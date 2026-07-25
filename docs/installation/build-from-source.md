---
icon: material/file-code
---

# Build from source

## :material-graph: Requirements

* Go 1.26 or later

You can download and install Go from: https://go.dev/doc/install, latest version is recommended.

## :material-fast-forward: Build

```bash
make
```

To enable `oixcloud://` managed subscriptions, inject the subscription signing key at link time through the build variable:

```bash
OIXCLOUD_SUBSCRIPTION_HMAC_KEY='your-key' make build
```

You can also copy `.env.example` to `.env` and set `OIXCLOUD_SUBSCRIPTION_HMAC_KEY` there. `make` and `make build` load `.env` automatically when the key is not already provided through the environment.

The key is optional for local builds. A binary built without it works normally for HTTP, file, and other subscription sources, but rejects `oixcloud://` with an explicit error. Official Docker images and release packages require the repository secret with the same name. Docker builds pass it as a BuildKit secret so it is not stored in an image layer or build argument:

```bash
docker build \
  --secret id=oixcloud_hmac_key,env=OIXCLOUD_SUBSCRIPTION_HMAC_KEY \
  -t serenity .
```

Or build and install binary to `$GOBIN`:

```bash
make install
```
