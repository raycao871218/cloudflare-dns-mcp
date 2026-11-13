# Cloudflare DNS MCP adapter

This Python module exposes four Streamable HTTP MCP tools for an existing DNS management backend: list zones, list records, preview a change, and apply a preview.

Install the dependency with `python -m pip install -r requirements.txt`. Import `create_mcp` and provide your async DNS handlers, member lookup, Pydantic request models, and API exception type. Enter `mcp.session_manager.run()` in the host ASGI lifespan and mount the returned ASGI application at the root after the host routes. The adapter handles `/mcp` and expects an individual Bearer token. Member lookup returns a name and one of `read`, `write`, or `admin`, or None for an invalid token.

The host backend owns credential storage, DNS changes, and audit records. Its preview handler returns a dictionary with `previewId` and `expiresAt`. Its apply model accepts `previewId`. The API exception provides a `message` attribute.

Loopback hosts are allowed by default. Set `DNS_MCP_ALLOWED_HOSTS` to a comma-separated list of exact hostnames, with a port where needed, to use an HTTPS reverse proxy.

Example Codex configuration

```toml
[mcp_servers.company_dns]
url = "https://dns.example.com/mcp"
bearer_token_env_var = "DNS_MCP_TOKEN"
default_tools_approval_mode = "writes"
```
