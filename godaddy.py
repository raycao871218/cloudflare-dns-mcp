import os
import re
from urllib.parse import quote, urljoin
from uuid import uuid4

import httpx


WRITABLE_TYPES = frozenset(("A", "AAAA", "CNAME", "MX", "TXT"))


class GoDaddy:
    provider = "godaddy"

    def __init__(self, token, api_error):
        self.error = api_error
        self.client = httpx.AsyncClient(
            base_url="https://api.godaddy.com/v3/domains/",
            headers={"Authorization": f"Bearer {token}"},
            timeout=12,
            proxy=os.getenv("GODADDY_HTTPS_PROXY") or None,
        )

    async def call(self, path, method="GET", payload=None):
        headers = {"Idempotency-Key": str(uuid4())} if method != "GET" else {}
        try:
            response = await self.client.request(method, path, json=payload, headers=headers)
            if response.is_success:
                return response.json() if response.content else None
        except (httpx.HTTPError, ValueError) as error:
            raise self.error(502, "GoDaddy request failed. Check current DNS before retrying a write.") from error
        if response.status_code == 404:
            raise self.error(404, "GoDaddy domain or record not found.")
        if response.status_code == 403:
            raise self.error(403, "GoDaddy rejected this operation. Check the server token's permissions.")
        raise self.error(502, f"GoDaddy DNS API returned HTTP {response.status_code}.")

    async def pages(self, path):
        first = self.client.build_request("GET", path).url
        url = first
        seen = set()
        items = []
        while url not in seen:
            seen.add(url)
            result = await self.call(url)
            if not isinstance(result, dict) or not isinstance(result.get("items"), list):
                raise self.error(502, "Unexpected GoDaddy list response.")
            items.extend(result["items"])
            next_url = next((link["href"] for link in result.get("links", []) if link["rel"] == "next"), None)
            if not next_url:
                return items
            url = httpx.URL(urljoin(str(url), next_url))
            if (url.scheme, url.netloc, url.path) != (first.scheme, first.netloc, first.path):
                break
        raise self.error(502, "Invalid GoDaddy pagination link.")

    @staticmethod
    def hosted(domain):
        servers = domain.get("nameServers") or []
        return domain.get("status") == "ACTIVE" and bool(servers) and all(
            re.fullmatch(r"ns[0-9]+\.domaincontrol\.com", server.lower().rstrip(".")) for server in servers
        )

    @staticmethod
    def zone_info(domain):
        return {"name": domain["domain"].lower(), "status": "active", "provider": "godaddy"}

    async def zones(self):
        return [self.zone_info(item) for item in await self.pages("domain-names") if self.hosted(item)]

    async def zone(self, domain):
        item = await self.call(f"domain-names/{quote(domain, safe='')}")
        if not self.hosted(item):
            raise self.error(404, "Active GoDaddy-hosted DNS zone not found.")
        return self.zone_info(item)

    @staticmethod
    def record(raw, domain):
        name = raw["name"].lower().rstrip(".")
        if name == "@":
            name = domain
        elif name != domain and not name.endswith("." + domain):
            name = f"{name}.{domain}"
        record = {"id": raw["recordId"], "name": name, "type": raw["type"],
                  "content": raw["data"], "ttl": raw["ttl"]}
        if raw.get("priority") is not None:
            record["priority"] = raw["priority"]
        return record

    async def records(self, path, name=None):
        domain = path.split("/")[1]
        records = [self.record(raw, domain) for raw in await self.pages(path)]
        return [record for record in records if name is None or record["name"] == name]

    async def snapshot(self, path, names):
        return sorted((record for record in await self.records(path) if record["name"] in names),
                      key=lambda record: record["id"])

    def payload(self, record, domain):
        if record["type"] not in WRITABLE_TYPES:
            raise self.error(400, "GoDaddy writes support A, AAAA, CNAME, MX and TXT.")
        if not 600 <= record["ttl"] <= 86400:
            raise self.error(400, "GoDaddy TTL must be between 600 and 86400 seconds.")
        if not isinstance(record.get("content"), str) or not record["content"].strip():
            raise self.error(400, "GoDaddy requires a record value.")
        if record.get("proxied") or record.get("comment") or record.get("data") is not None:
            raise self.error(400, "Unsupported GoDaddy record fields.")
        payload = {"type": record["type"], "data": record["content"], "ttl": record["ttl"],
                   "name": "@" if record["name"] == domain else record["name"].removesuffix("." + domain)}
        if record["type"] == "MX":
            payload["priority"] = record.get("priority", 10)
        return payload
