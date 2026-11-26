import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import quote
from uuid import UUID, uuid4

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, FastAPI, Request, Security
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from database import Database
from dns_mcp import create_mcp
from godaddy import GoDaddy, WRITABLE_TYPES

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
load_dotenv(ROOT / ".env")

RECORD_FIELDS = {"id", "name", "type", "content", "ttl", "proxied", "priority", "comment", "data"}
PROXIED_TYPES = {"A", "AAAA", "CNAME"}
DNS_NAME = re.compile(r"(?:\*\.)?(?:[a-z0-9_-]{1,63}\.)+[a-z0-9-]{1,63}")
LOCAL_HOST = re.compile(r"(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]+)?", re.IGNORECASE)
LOG = logging.getLogger("uvicorn.error")
PANEL_COOKIE = "dns_panel_session"
PANEL_SESSION_SECONDS = 7 * 24 * 60 * 60


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message


class RecordChange(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str | None = None
    type: Literal["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS", "PTR"] | None = None
    content: str | None = None
    ttl: int | None = Field(default=None, ge=1)
    proxied: bool | None = None
    priority: int | None = Field(default=None, ge=0, le=65535)
    comment: str | None = None
    data: dict[str, Any] | None = None


class CreateChange(BaseModel):
    domain: str
    source: str | None = None
    action: Literal["create"]
    record: RecordChange


class UpdateChange(BaseModel):
    domain: str
    source: str | None = None
    action: Literal["update"]
    recordId: str = Field(pattern=r"^[A-Za-z0-9_-]{1,160}$")
    record: RecordChange


class DeleteChange(BaseModel):
    domain: str
    source: str | None = None
    action: Literal["delete"]
    recordId: str = Field(pattern=r"^[A-Za-z0-9_-]{1,160}$")


Change = Annotated[CreateChange | UpdateChange | DeleteChange, Field(discriminator="action")]


class ApplyRequest(BaseModel):
    previewId: UUID


class ZoneInfo(BaseModel):
    name: str
    status: str
    account: str | None = None
    provider: Literal["cloudflare", "godaddy"]
    source: str


class ZonesResponse(BaseModel):
    zones: list[ZoneInfo]
    warnings: list[str] = Field(default_factory=list)
    sources: list["SourceInfo"]


class SourceInfo(BaseModel):
    name: str
    provider: Literal["cloudflare", "godaddy"]
    token_validity: Literal["permanent", "one_year"]
    expires_on: str | None = None


class RecordInfo(BaseModel):
    id: str | None = None
    name: str | None = None
    type: str | None = None
    content: str | None = None
    ttl: int | None = None
    proxied: bool | None = None
    priority: int | None = None
    comment: str | None = None
    data: dict[str, Any] | None = None


class RecordsResponse(BaseModel):
    domain: str
    source: str
    records: list[RecordInfo]


class PreviewResponse(BaseModel):
    previewId: UUID
    expiresAt: datetime
    action: str
    domain: str
    source: str
    before: RecordInfo | None
    after: RecordInfo | None


class ApplyResponse(BaseModel):
    domain: str
    action: str
    record: RecordInfo


class ErrorResponse(BaseModel):
    error: str
    issues: list[dict[str, str]] | None = None


@dataclass
class Plan:
    domain: str
    action: str
    path: str
    record_id: str | None
    change: dict | None
    names: set[str]
    snapshot: list[dict]
    expires: float
    member: str
    channel: str
    before: dict | None
    proposed: dict | None
    provider: str
    source: str


class Cloudflare:
    provider = "cloudflare"

    def __init__(self, token: str, account: str | None):
        self.token = token
        self.account = account
        self.client = httpx.AsyncClient(
            base_url="https://api.cloudflare.com/client/v4/",
            headers={"Authorization": "Bearer " + token},
            timeout=12,
        )

    async def call(self, path, method="GET", payload=None, params=None):
        try:
            response = await self.client.request(method, path, json=payload, params=params)
            body = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise ApiError(502, "Cloudflare request failed. Check current DNS before retrying a write.") from error
        if not response.is_success or not body.get("success"):
            errors = "; ".join(f"{error.get('code')} {error.get('message')}" for error in body.get("errors", []))
            message = f"Cloudflare HTTP {response.status_code}: {errors}".replace(self.token, "[redacted]")
            raise ApiError(502, message)
        return body

    async def list(self, path, filters=None, per_page=100):
        items = []
        page = 1
        while True:
            params = {**(filters or {}), "page": page, "per_page": per_page}
            body = await self.call(path, params=params)
            result = body["result"]
            items.extend(result)
            info = body.get("result_info") or {}
            if not result:
                break
            if info.get("total_pages") is not None:
                if page >= info["total_pages"]:
                    break
            elif info.get("total_count") is not None:
                if len(items) >= info["total_count"]:
                    break
            elif len(result) < per_page:
                break
            page += 1
        return items

    async def zones(self, name=None):
        filters = {"name": name} if name else {}
        if self.account:
            filters["account.id"] = self.account
        return await self.list("zones", filters, per_page=50)

    async def zone(self, domain):
        domain = fqdn(domain)
        matches = [zone for zone in await self.zones(domain) if zone["name"] == domain]
        if not matches:
            raise ApiError(404, "Zone not visible to this token.")
        if len(matches) > 1:
            raise ApiError(409, "Configure CLOUDFLARE_ACCOUNT_ID to disambiguate this zone.")
        return matches[0]

    async def snapshot(self, path, names):
        groups = await asyncio.gather(*(self.list(path, {"name.exact": name}) for name in names))
        return sorted((record for group in groups for record in group), key=lambda record: record["id"])


def fqdn(value):
    name = value.lower().removesuffix(".")
    if len(name) > 253 or not DNS_NAME.fullmatch(name):
        raise ApiError(400, "Use an ASCII fully qualified DNS name (Punycode for IDNs).")
    return name


def record_path(zone):
    return f"zones/{quote(zone['id'], safe='')}/dns_records"


def view(record):
    return {key: value for key, value in record.items() if key in RECORD_FIELDS}


def provider_accounts():
    """Load named credential references and retain the original environment settings."""
    entries = json.loads(os.getenv("DNS_PROVIDER_ACCOUNTS", "[]"))
    if not isinstance(entries, list):
        raise RuntimeError("DNS_PROVIDER_ACCOUNTS must be a JSON array.")
    entries = [*entries]
    for provider, token_env, default_name in (
        ("cloudflare", "CLOUDFLARE_API_TOKEN", "Cloudflare 默认"),
        ("godaddy", "GODADDY_PAT", "GoDaddy 默认"),
    ):
        if os.getenv(token_env) and not any(isinstance(e, dict) and e.get("token_env") == token_env for e in entries):
            entries.append({"provider": provider, "token_env": token_env, "name": default_name,
                            "account_id": os.getenv("CLOUDFLARE_ACCOUNT_ID") if provider == "cloudflare" else None})
    accounts = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuntimeError("Each DNS provider account must be an object.")
        name, provider, token_env = (entry.get(key) for key in ("name", "provider", "token_env"))
        if (not isinstance(name, str) or not name.strip() or len(name) > 80 or name in accounts
                or provider not in ("cloudflare", "godaddy")
                or not isinstance(token_env, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", token_env)
                or not os.getenv(token_env)):
            raise RuntimeError("Check DNS provider names, types and token environment variables.")
        token = os.environ[token_env]
        accounts[name] = (Cloudflare(token, entry.get("account_id")) if provider == "cloudflare"
                          else GoDaddy(token, ApiError))
        expires_on = entry.get("expires_on")
        if expires_on is not None:
            expires_on = datetime.strptime(expires_on, "%Y-%m-%d").date().isoformat()
        accounts[name].source_info = SourceInfo(
            name=name, provider=provider, expires_on=expires_on,
            token_validity="one_year" if provider == "godaddy" else "permanent",
        )
    if not accounts:
        raise RuntimeError("Configure at least one DNS provider account.")
    return accounts


@asynccontextmanager
async def lifespan(app):
    key = os.getenv("DNS_API_KEY")
    if not key or len(key) < 32:
        raise RuntimeError("Set DNS_API_KEY (32+ characters).")
    app.state.accounts = provider_accounts()
    app.state.key = key.encode()
    app.state.named_writes = os.getenv("DNS_REQUIRE_NAMED_WRITES") == "true"
    app.state.panel_auto_login = os.getenv("DNS_PANEL_AUTO_LOGIN") == "true"
    app.state.plans = {}
    app.state.write_lock = asyncio.Lock()
    app.state.audit = await Database.open()
    try:
        await app.state.audit.initialize(load_mcp_members())
        async with mcp.session_manager.run():
            yield
    finally:
        await app.state.audit.close()
        await asyncio.gather(*(account.client.aclose() for account in app.state.accounts.values()))


app = FastAPI(
    title="Cloudflare DNS API",
    description="查询 DNS 记录。写入时先创建预览，再应用单次变更。受保护的接口使用 DNS_API_KEY。",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)


@app.exception_handler(ApiError)
async def api_error(request, error):
    return JSONResponse({"error": error.message}, status_code=error.status)


@app.exception_handler(RequestValidationError)
async def validation_error(request, error):
    issues = [
        {"field": ".".join(map(str, issue["loc"])), "message": issue["msg"]}
        for issue in error.errors()
    ]
    return JSONResponse({"error": "Invalid request.", "issues": issues}, status_code=422)


@app.middleware("http")
async def response_headers(request, call_next):
    length = request.headers.get("content-length")
    if request.method == "POST" and length and length.isdecimal() and int(length) > 16_384:
        return JSONResponse({"error": "Request too large."}, status_code=413)
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


bearer = HTTPBearer(auto_error=False, scheme_name="ServiceKey", description="输入个人成员凭证或服务端 DNS_API_KEY。")


async def require_key(request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer)]):
    credential = credentials.credentials if credentials else ""
    digest = credential_digest(credential) if credential else None
    if credentials is None and request.headers.get("x-dns-panel") == "1":
        digest = panel_session_digest(request)
    member = await find_member_by_digest(request, digest)
    if member:
        request.state.actor, request.state.role = member
        request.state.channel = "web-api"
        request.state.credential_hash = digest
    elif ((credential and hmac.compare_digest(credential.encode(), request.app.state.key))
          or (not credential and digest == "shared")):
        request.state.actor, request.state.role, request.state.channel = "shared-key", "write", "shared-api"
    else:
        raise ApiError(401, "Invalid API key.")


async def find_member(request, credential):
    return await find_member_by_digest(request, credential_digest(credential) if credential else None)


def credential_digest(credential):
    return hashlib.sha256(credential.encode()).hexdigest()


async def find_member_by_digest(request, digest):
    if not digest or digest == "shared":
        return None
    row = await request.app.state.audit.one(
        "SELECT name, role FROM dns_members WHERE credential_hash = ? AND revoked_at IS NULL", (digest,)
    )
    return (row["name"], row["role"]) if row else None


def require_admin(request):
    if request.state.role != "admin":
        raise ApiError(403, "A personal admin credential is required.")


async def require_write(request):
    credential = getattr(request.state, "credential", None)
    digest = getattr(request.state, "credential_hash", None)
    if credential is not None:
        digest = credential_digest(credential)
    if digest is not None and not await find_member_by_digest(request, digest):
        raise ApiError(401, "This credential was revoked or replaced.")
    if effective_role(request) not in ("write", "admin"):
        raise ApiError(403, "Use a personal write or admin credential to change DNS.")


def effective_role(request):
    if request.app.state.named_writes and request.state.channel in ("local-panel", "shared-api"):
        return "read"
    return request.state.role


async def identity(request: Request):
    return {"actor": request.state.actor, "role": effective_role(request), "channel": request.state.channel}


async def audit_events(request: Request, actor: str | None = None, before_id: int | None = None):
    """List DNS audit events, newest first. Requires a personal admin credential."""
    require_admin(request)
    conditions, params = [], []
    if actor:
        conditions.append("actor = ?")
        params.append(actor)
    if before_id is not None:
        conditions.append("id < ?")
        params.append(before_id)
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    rows = await request.app.state.audit.fetch(
        "SELECT * FROM dns_audit" + where + " ORDER BY id DESC LIMIT 51", params
    )
    events = []
    for row in rows[:50]:
        event = dict(row)
        for field in ("before", "after"):
            event[field] = json.loads(event.pop(field + "_json"))
        events.append(event)
    return {"events": events, "nextBeforeId": events[-1]["id"] if len(rows) > 50 else None}



def require_local_panel(request: Request):
    host = request.headers.get("host", "")
    same_origin = request.headers.get("sec-fetch-site") == "same-origin"
    valid_origin = request.method == "GET" or request.headers.get("origin") in (f"http://{host}", f"https://{host}")
    if not (request.app.state.panel_auto_login and LOCAL_HOST.fullmatch(host) and same_origin and valid_origin):
        raise ApiError(401, "Local panel access is unavailable.")
    request.state.actor, request.state.role, request.state.channel = "local-panel", "write", "local-panel"


async def get_zones(request: Request):
    """列出域名、托管商和令牌名称。"""
    accounts = request.app.state.accounts
    results = await asyncio.gather(*(account.zones() for account in accounts.values()), return_exceptions=True)
    zones = []
    warnings = []
    for (source, account), result in zip(accounts.items(), results):
        if isinstance(result, ApiError):
            warnings.append(f"{source}: {result.message}")
            continue
        if isinstance(result, BaseException):
            raise result
        zones.extend({"name": zone["name"], "status": zone["status"], "provider": account.provider,
                      "source": source, "account": (zone.get("account") or {}).get("name")} for zone in result)
    active = {zone["name"] for zone in zones if zone["status"] == "active"}
    zones = [zone for zone in zones if zone["status"] == "active" or zone["name"] not in active]
    return {"zones": sorted(zones, key=lambda zone: (zone["name"], zone["source"])), "warnings": warnings,
            "sources": [account.source_info.model_dump() for account in accounts.values()]}


async def resolve_zone(request, domain, source=None):
    domain = fqdn(domain)
    accounts = request.app.state.accounts
    if source is not None:
        if source not in accounts:
            raise ApiError(404, "Unknown DNS source.")
        accounts = {source: accounts[source]}
    results = await asyncio.gather(*(account.zone(domain) for account in accounts.values()), return_exceptions=True)
    matches = []
    errors = []
    for (name, account), result in zip(accounts.items(), results):
        if isinstance(result, ApiError):
            if result.status != 404:
                errors.append(result)
            continue
        if isinstance(result, BaseException):
            raise result
        path = record_path(result) if account.provider == "cloudflare" else f"zones/{domain}/dns-records"
        matches.append((account, result, path, name))
    candidates = [match for match in matches if match[1]["status"] == "active"] or matches
    if len(candidates) > 1:
        raise ApiError(409, "This domain matches multiple accounts. Specify source from list_zones.")
    if errors:
        raise errors[0]
    if not candidates:
        raise ApiError(404, "Zone not visible to the configured providers.")
    return candidates[0]


async def get_records(request: Request, domain: str, name: str | None = None, source: str | None = None):
    """读取指定域名的全部记录。name 可按完整主机名筛选。"""
    cf, zone, path, source = await resolve_zone(request, domain, source)
    name = fqdn(name) if name else None
    if cf.provider == "godaddy":
        records = await cf.records(path, name)
    else:
        records = await cf.list(path, {"name.exact": name} if name else {})
    return {"domain": zone["name"], "source": source, "records": [view(record) for record in records]}


async def preview(request: Request, body: Change):
    """生成新增、修改或删除的预览。预览五分钟内有效。"""
    await require_write(request)
    cf, zone, path, source = await resolve_zone(request, body.domain, body.source)
    godaddy = cf.provider == "godaddy"
    if zone["status"] != "active":
        raise ApiError(409, "Zone must be active.")
    action = body.action
    change = None if isinstance(body, DeleteChange) else body.record.model_dump(exclude_none=True)
    if change is not None and not change:
        raise ApiError(400, "Invalid record fields.")
    if change and "name" in change:
        change["name"] = fqdn(change["name"])
        if change["name"] != zone["name"] and not change["name"].endswith("." + zone["name"]):
            raise ApiError(400, "The record name must belong to the selected zone.")

    before = None
    record_id = None
    if isinstance(body, CreateChange):
        if not change.get("name") or not change.get("type") or not {"content", "data"} & change.keys():
            raise ApiError(400, "Create requires name, type and content or data.")
        if not godaddy and change["type"] in PROXIED_TYPES:
            change.setdefault("proxied", False)
        change.setdefault("ttl", 600 if godaddy else 1)
        if godaddy and change["type"] == "MX":
            change.setdefault("priority", 10)
    else:
        record_id = body.recordId
        if godaddy:
            before = next((item for item in await cf.records(path) if item["id"] == record_id), None)
            if before is None:
                raise ApiError(404, "GoDaddy record not found.")
            if before["type"] not in WRITABLE_TYPES:
                raise ApiError(400, "GoDaddy writes support A, AAAA, CNAME, MX and TXT.")
        else:
            if not re.fullmatch(r"[a-f0-9]{32}", record_id):
                raise ApiError(400, "Invalid Cloudflare record ID.")
            before = (await cf.call(f"{path}/{record_id}"))["result"]
        if change and "type" in change and change["type"] != before["type"]:
            raise ApiError(400, "Use separate create and delete plans to change type.")
    if change and change.get("proxied") is True:
        change["ttl"] = 1

    names = {record["name"] for record in (before, change) if record and "name" in record}
    records = await cf.snapshot(path, names)
    if before and not any(item.get("modified_on") == before.get("modified_on") and view(item) == view(before) for item in records):
        raise ApiError(409, "Record changed during preview.")
    if action == "create" and not change.get("data") and any(
        item["type"] == change["type"] and item.get("content") == change.get("content")
        and item.get("priority") == change.get("priority") for item in records
    ):
        raise ApiError(409, "An equivalent record already exists.")

    plans = request.app.state.plans
    now = time.monotonic()
    for expired in [key for key, plan in plans.items() if plan.expires <= now]:
        del plans[expired]
    if len(plans) >= 500:
        raise ApiError(429, "Too many pending previews.")
    preview_id = uuid4()
    await require_write(request)
    previous = view(before) if before else None
    proposed = None if change is None else {**(previous or {}), **change}
    payload = cf.payload(proposed, zone["name"]) if godaddy and proposed else change
    plans[preview_id] = Plan(zone["name"], action, path, record_id, payload, names, records, now + 300,
                             request.state.actor, request.state.channel, previous, proposed, cf.provider, source)
    return {
        "previewId": preview_id,
        "expiresAt": datetime.now(timezone.utc) + timedelta(minutes=5),
        "action": action,
        "domain": zone["name"],
        "source": source,
        "before": previous,
        "after": proposed,
    }


async def apply(request: Request, body: ApplyRequest):
    """应用一次预览。执行前重新读取相关记录，检测到变化时拒绝写入。"""
    await require_write(request)
    plans = request.app.state.plans
    plan = plans.get(body.previewId)
    if plan is None or plan.expires <= time.monotonic():
        plans.pop(body.previewId, None)
        raise ApiError(404, "Preview missing, consumed or expired.")
    if (plan.member, plan.channel) != (request.state.actor, request.state.channel):
        raise ApiError(404, "Preview not found for this member.")
    lock = request.app.state.write_lock
    if lock.locked():
        raise ApiError(409, "Another change is in progress.")
    async with lock:
        del plans[body.previewId]
        cf, zone, current_path, _ = await resolve_zone(request, plan.domain, plan.source)
        if cf.provider != plan.provider or current_path != plan.path or zone["status"] != "active":
            raise ApiError(409, "DNS provider changed after preview.")
        if await cf.snapshot(plan.path, plan.names) != plan.snapshot:
            raise ApiError(409, "DNS changed after preview. Review a fresh preview.")
        method = {"create": "POST", "update": "PUT" if plan.provider == "godaddy" else "PATCH",
                  "delete": "DELETE"}[plan.action]
        path = f"{plan.path}/{plan.record_id}" if plan.record_id else plan.path
        await require_write(request)
        database = request.app.state.audit
        event = await database.one("""
                INSERT INTO dns_audit (created_at, actor, channel, domain, action, status, before_json, after_json)
                VALUES (?, ?, ?, ?, ?, 'unconfirmed', ?, ?) RETURNING id
            """, (datetime.now(timezone.utc).isoformat(), plan.member, plan.channel, plan.domain,
                  plan.action, json.dumps(plan.before), json.dumps(plan.proposed)))
        result = await cf.call(path, method, plan.change)
        if plan.provider == "godaddy":
            record = {"id": plan.record_id} if plan.action == "delete" else cf.record(result, plan.domain)
        else:
            record = result["result"]
        actual = None if plan.action == "delete" else view(record)
        await database.execute("UPDATE dns_audit SET status = 'applied', after_json = ? WHERE id = ?",
                               (json.dumps(actual), event['id']))
        LOG.info("dns_change action=%s domain=%s record_id=%s member=%s",
                 plan.action, plan.domain, record["id"], plan.member)
        return {"domain": plan.domain, "action": plan.action, "record": view(record)}


class NewMember(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_.@-]{1,80}$")
    role: Literal["read", "write", "admin"] = "read"


async def list_members(request: Request):
    require_admin(request)
    rows = await request.app.state.audit.fetch(
        "SELECT name, role, issued_at, revoked_at FROM dns_members ORDER BY LOWER(name), name"
    )
    return {"members": [dict(row) for row in rows]}


async def create_member(request: Request, body: NewMember):
    require_admin(request)
    if body.name.casefold() in ("shared-key", "local-panel"):
        raise ApiError(400, "This member name is reserved.")
    database = request.app.state.audit
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    if not await database.create_member(body.name, body.role, digest, now):
        raise ApiError(409, "This member name already exists.")
    return {"name": body.name, "role": body.role, "token": token}


async def managed_member(request, name):
    require_admin(request)
    if name == request.state.actor:
        raise ApiError(409, "Use another administrator to manage your own credential.")
    row = await request.app.state.audit.one("SELECT role FROM dns_members WHERE name = ?", (name,))
    if not row:
        raise ApiError(404, "Member not found.")
    return row["role"]


def discard_member_previews(request, name):
    plans = request.app.state.plans
    for preview_id in [key for key, plan in plans.items() if plan.member == name]:
        del plans[preview_id]


async def rotate_member(request: Request, name: str):
    role = await managed_member(request, name)
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    database = request.app.state.audit
    await database.execute(
        "UPDATE dns_members SET credential_hash = ?, issued_at = ?, revoked_at = NULL WHERE name = ?",
        (digest, now, name),
    )
    discard_member_previews(request, name)
    return {"name": name, "role": role, "token": token}


async def revoke_member(request: Request, name: str):
    await managed_member(request, name)
    database = request.app.state.audit
    await database.execute(
        "UPDATE dns_members SET revoked_at = COALESCE(revoked_at, ?) WHERE name = ?",
        (datetime.now(timezone.utc).isoformat(), name),
    )
    discard_member_previews(request, name)
    return {"name": name, "revoked": True}


for prefix, dependency in (("/v1", require_key), ("/panel-api/v1", require_local_panel)):
    router = APIRouter(
        prefix=prefix,
        dependencies=[Depends(dependency)],
        include_in_schema=prefix == "/v1",
        responses={status: {"model": ErrorResponse} for status in (400, 401, 404, 409, 422, 502)},
    )
    router.add_api_route("/me", identity, methods=["GET"], summary="当前身份")
    if prefix == "/v1":
        router.add_api_route("/audit", audit_events, methods=["GET"], summary="查询 DNS 审计记录")
        router.add_api_route("/members", list_members, methods=["GET"], summary="查看成员")
        router.add_api_route("/members", create_member, methods=["POST"], summary="创建成员并签发凭证")
        router.add_api_route("/members/{name}/rotate", rotate_member, methods=["POST"], summary="重新签发个人凭证")
        router.add_api_route("/members/{name}/revoke", revoke_member, methods=["POST"], summary="撤销个人凭证")
    router.add_api_route("/zones", get_zones, methods=["GET"], summary="查询域名", response_model=ZonesResponse)
    router.add_api_route("/records", get_records, methods=["GET"], summary="查询 DNS 记录",
                         response_model=RecordsResponse, response_model_exclude_unset=True)
    router.add_api_route("/preview", preview, methods=["POST"], summary="预览 DNS 变更",
                         response_model=PreviewResponse, response_model_exclude_unset=True)
    router.add_api_route("/apply", apply, methods=["POST"], summary="应用 DNS 变更",
                         response_model=ApplyResponse, response_model_exclude_unset=True)
    app.include_router(router)


@app.get("/healthz", summary="检查服务状态")
async def health():
    return {"status": "ok"}


def panel_session_signature(request, payload):
    return hmac.new(request.app.state.key, f"dns-panel:{payload}".encode(), "sha256").hexdigest()


def panel_session_digest(request):
    cookie = request.cookies.get(PANEL_COOKIE, "")
    match = re.fullmatch(r"(shared|[0-9a-f]{64})\.([0-9]{1,12})\.([0-9a-f]{64})", cookie)
    if not match:
        return None
    digest, expires, signature = match.groups()
    if int(expires) <= time.time():
        return None
    if not hmac.compare_digest(signature, panel_session_signature(request, f"{digest}.{expires}")):
        return None
    return digest


@app.post("/panel-session", include_in_schema=False)
async def start_panel_session(request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer)]):
    if request.headers.get("x-dns-panel") != "1" or credentials is None:
        raise ApiError(401, "Invalid API key.")
    await require_key(request, credentials)
    digest = getattr(request.state, "credential_hash", "shared")
    expires = int(time.time()) + PANEL_SESSION_SECONDS
    payload = f"{digest}.{expires}"
    response = JSONResponse(await identity(request))
    response.set_cookie(
        PANEL_COOKIE, f"{payload}.{panel_session_signature(request, payload)}",
        max_age=PANEL_SESSION_SECONDS, httponly=True, samesite="strict", secure=request.url.scheme == "https",
    )
    return response


@app.delete("/panel-session", include_in_schema=False)
async def end_panel_session(request: Request):
    if request.headers.get("x-dns-panel") != "1":
        raise ApiError(403, "Invalid panel request.")
    response = JSONResponse({"status": "ok"})
    response.delete_cookie(PANEL_COOKIE, httponly=True, samesite="strict", secure=request.url.scheme == "https")
    return response


@app.get("/docs", include_in_schema=False)
async def swagger_ui():
    response = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title="Cloudflare DNS API · Swagger UI",
        swagger_js_url="/swagger/swagger-ui-bundle.js",
        swagger_css_url="/swagger/swagger-ui.css",
        swagger_favicon_url="data:,",
        swagger_ui_parameters={"persistAuthorization": False, "validatorUrl": None},
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@app.get("/", include_in_schema=False)
async def panel():
    return FileResponse(WEB / "index.html", headers={
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    })


@app.get("/panel.js", include_in_schema=False)
async def panel_script():
    return FileResponse(WEB / "panel.js", media_type="text/javascript")


@app.get("/panel.css", include_in_schema=False)
async def panel_style():
    return FileResponse(WEB / "panel.css", media_type="text/css")


@app.get("/swagger/swagger-ui-bundle.js", include_in_schema=False)
async def swagger_script():
    return FileResponse(WEB / "swagger" / "swagger-ui-bundle.js", media_type="text/javascript")


@app.get("/swagger/swagger-ui.css", include_in_schema=False)
async def swagger_style():
    return FileResponse(WEB / "swagger" / "swagger-ui.css", media_type="text/css")


def load_mcp_members():
    """Load named member credentials as SHA-256 hashes and roles."""
    try:
        config = json.loads(os.getenv("DNS_MCP_MEMBERS", "{}"))
        if not isinstance(config, dict):
            raise ValueError
        members = {}
        for member, entry in config.items():
            if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,80}", member) or not isinstance(entry, dict):
                raise ValueError
            digest = entry.get("sha256")
            role = entry.get("role")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError
            if role not in ("read", "write", "admin") or digest in members:
                raise ValueError
            members[digest] = (member, role)
        return members
    except (TypeError, ValueError) as error:
        raise RuntimeError("DNS_MCP_MEMBERS must contain unique SHA-256 hashes and read/write/admin roles.") from error


mcp, protected_mcp = create_mcp(
    get_zones=get_zones, get_records=get_records, preview=preview, apply=apply,
    find_member=find_member, change_type=Change, apply_type=ApplyRequest, api_error=ApiError,
)


app.mount("/", protected_mcp)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.getenv("BIND_HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8788")))
