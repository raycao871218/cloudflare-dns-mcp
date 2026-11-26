import argparse
import asyncio
import os
from pathlib import Path

from dotenv import load_dotenv

from database import Database


async def migrate(filename):
    if not os.getenv("DATABASE_URL", "").strip():
        raise ValueError("Set DATABASE_URL to the target PostgreSQL connection string.")
    db = await Database.open()
    try:
        await db.initialize()
        members, events = await db.import_sqlite(filename)
    finally:
        await db.close()
    print(f"Migrated {members} members and {events} audit events.")


if __name__ == "__main__":
    load_dotenv(Path(__file__).resolve().with_name(".env"))
    parser = argparse.ArgumentParser(description="Copy the DNS service SQLite data into an empty PostgreSQL database.")
    parser.add_argument("--source", default=os.getenv("DNS_AUDIT_DB", "/data/audit.sqlite3"))
    args = parser.parse_args()
    try:
        asyncio.run(migrate(args.source))
    except Exception as error:
        parser.exit(1, f"Migration failed: {error}\n")
