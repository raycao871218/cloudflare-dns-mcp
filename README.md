# Company DNS Manager

Python/FastAPI service with Web panel, REST API and Streamable HTTP MCP for Cloudflare and GoDaddy. Supports multiple named accounts, member credentials, change previews, audit logs, PostgreSQL and token expiry countdowns.

## Deploy

Install Git, Docker and Compose, then run:

```sh
git clone https://github.com/raycao871218/cloudflare-dns-mcp.git cloudflare-dns-manager
cd cloudflare-dns-manager
cp .env.example .env
chmod 600 .env
```

Configure DNS_API_KEY, provider credentials and DATABASE_URL in .env. PostgreSQL needs an existing database and a role allowed to create and update application tables. Without DATABASE_URL, data uses the persistent SQLite volume.

For the first administrator, run python mcp_member.py admin --role admin. Save the personal token and put the printed hash entry in DNS_MCP_MEMBERS. Manage later members in the panel.

```sh
docker compose up -d --build --wait
```

The service binds to 127.0.0.1:8788. Routes are / for the panel, /docs for Swagger, /healthz for health and /mcp for MCP. Configure a reverse proxy forwarding Host and Authorization for team access. Add its hostname and port to DNS_MCP_ALLOWED_HOSTS.

Browser logins persist for seven days. Set DNS_PANEL_AUTO_LOGIN=false for named logins and DNS_REQUIRE_NAMED_WRITES=true to require individual credentials for writes.

## Named accounts

Store tokens in server environment variables and reference their names:

```dotenv
CLOUDFLARE_API_TOKEN=
GODADDY_PAT=
GODADDY_PAT_OTHER=
DNS_PROVIDER_ACCOUNTS=[{"name":"Company Cloudflare","provider":"cloudflare","token_env":"CLOUDFLARE_API_TOKEN"},{"name":"Company GoDaddy","provider":"godaddy","token_env":"GODADDY_PAT","expires_on":"2027-12-31"},{"name":"Other GoDaddy","provider":"godaddy","token_env":"GODADDY_PAT_OTHER"}]
```

Use expires_on in YYYY-MM-DD format for countdowns and match the date to the provider's settings. Cloudflare defaults to permanent validity and GoDaddy displays one year when the actual expiry is unknown. Legacy token variables are included as default accounts unless explicitly named in DNS_PROVIDER_ACCOUNTS. Optional GODADDY_HTTPS_PROXY configures GoDaddy's outbound HTTP proxy.

Domains show their DNS provider and source account. GoDaddy-registered domains with Cloudflare nameservers are managed through Cloudflare. GoDaddy writes currently support A, AAAA, CNAME, MX and TXT with TTL 600–86400 seconds.

## MCP

```toml
[mcp_servers.company_dns]
url = "https://dns.example.internal/mcp"
bearer_token_env_var = "DNS_MCP_TOKEN"
```

Tools list zones, list DNS records, preview and apply changes. Results include provider and source. Specify source for domains visible through multiple accounts. Previews last five minutes and belong to their creator.

## Update

From the server checkout:

```sh
bash deploy.sh
```

The script pulls the current branch with fast-forward validation, builds the image and waits for Compose health. Keep real tokens, database credentials and member credentials in the server .env. Back up PostgreSQL separately.
