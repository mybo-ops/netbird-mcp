# Fork container publishing

This fork publishes the upstream NetBird MCP HTTP server as a multi-platform container:

```text
ghcr.io/mybo-ops/netbird-mcp:latest
```

The `Sync upstream and publish GHCR` workflow:

- runs every six hours and on manual dispatch;
- merges `netbirdio/netbird-mcp:main` into this fork without force-pushing;
- runs dependency installation, type-checking, and the upstream test suite;
- publishes only after those checks pass;
- publishes `latest`, `main`, and immutable `sha-<12-character-commit>` tags for `linux/amd64` and `linux/arm64`.

A merge conflict or failed test blocks publication and leaves the last known-good image in place.

## Runtime configuration

The image runs the Streamable HTTP entrypoint on port `3000`. For a single trusted MCPHub instance using a NetBird service-user PAT, deploy it on a private Docker network with:

```yaml
environment:
  NETBIRD_API_URL: https://vpn.callmea.dev
  NETBIRD_ENABLE_OAUTH: "false"
```

Configure MCPHub with transport `streamable-http`, URL `http://netbird-mcp:3000/mcp`, and send the PAT through the `x-netbird-token` request header. Keep the PAT in MCPHub or deployment secrets; never bake it into the image.

For reproducible deployments, use the immutable `sha-...` tag. Using `latest` follows successful automatic upstream builds but still requires the container platform to pull and recreate the running container.
