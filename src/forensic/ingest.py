import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import db


def sha256_chunked(file_path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def count_lines(file_path: Path) -> int:
    with open(file_path, "rb") as f:
        return sum(1 for _ in f)


def _write_manifest(case_dir: Path, conn, manifest_header: dict) -> None:
    """(Re)write manifest.json from ALL rows in the evidence table + manifest_header metadata."""
    rows = conn.execute(
        "SELECT id, filename, stored_path, sha256, size_bytes, line_count, "
        "collected_at_utc, host FROM evidence ORDER BY id"
    ).fetchall()
    manifest = dict(manifest_header)
    manifest["items"] = [
        {
            "id": r["id"],
            "filename": r["filename"],
            "stored_path": r["stored_path"],
            "sha256": r["sha256"],
            "size_bytes": r["size_bytes"],
            "line_count": r["line_count"],
            "collected_at_utc": r["collected_at_utc"],
            "host": r["host"],
        }
        for r in rows
    ]
    manifest_path = case_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    manifest_h = sha256_chunked(manifest_path)
    with open(case_dir / "manifest.sha256", "w", encoding="utf-8") as f:
        f.write(manifest_h)


def ingest(case_dir: Path, sources_json: Path, collector: str) -> None:
    with open(sources_json, "r", encoding="utf-8") as f:
        spec = json.load(f)

    case_id = spec["case_id"]
    year_hint = spec.get("year_hint")
    reference_host: str | None = spec.get("reference_host")

    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    conn = db.connect(case_dir)
    db.init_schema(conn)

    created_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn.execute("INSERT OR IGNORE INTO case_meta (key, value) VALUES (?, ?)", ("case_id", case_id))
    conn.execute(
        "INSERT OR IGNORE INTO case_meta (key, value) VALUES (?, ?)",
        ("created_at_utc", created_at_utc),
    )
    conn.execute(
        "INSERT OR IGNORE INTO case_meta (key, value) VALUES (?, ?)", ("tool_version", "0.1.0")
    )
    if year_hint:
        conn.execute(
            "INSERT OR IGNORE INTO case_meta (key, value) VALUES (?, ?)",
            ("year_hint", str(year_hint)),
        )
    if reference_host:
        conn.execute(
            "INSERT OR IGNORE INTO case_meta (key, value) VALUES (?, ?)",
            ("reference_host", reference_host),
        )
    conn.commit()

    manifest_header = {
        "case_id": case_id,
        "tool_version": "0.1.0",
        "created_at_utc": created_at_utc,
        "collector": collector,
        "hash_algorithm": "SHA-256",
    }

    # Read existing evidence hashes to detect duplicates
    existing_hashes = {row["sha256"] for row in conn.execute("SELECT sha256 FROM evidence")}

    for src in spec["sources"]:
        data_path = sources_json.parent / src["path"]
        if not data_path.exists():
            print(f"MISSING {data_path}")
            continue

        h = sha256_chunked(data_path)
        if h in existing_hashes:
            print(f"duplicate, skipped {data_path}")
            continue

        host = src["host"]
        basename = data_path.name
        dest = evidence_dir / f"{host}__{basename}"

        shutil.copy2(data_path, dest)

        assert sha256_chunked(dest) == h

        os.chmod(dest, 0o444)

        line_count = count_lines(dest)
        size_bytes = dest.stat().st_size
        collected_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        db.insert_evidence(
            conn,
            filename=basename,
            stored_path=f"evidence/{dest.name}",
            sha256=h,
            size_bytes=size_bytes,
            line_count=line_count,
            collected_at_utc=collected_at_utc,
            collector=collector,
            host=host,
            source_type=src["source_type"],
            declared_tz=src["declared_tz"],
        )

        existing_hashes.add(h)

    # Always rebuild manifest from ALL evidence rows (fixes Bug 2: re-run wipes manifest)
    _write_manifest(case_dir, conn, manifest_header)
    conn.close()


def verify(case_dir: Path) -> bool:
    manifest_path = case_dir / "manifest.json"
    manifest_h_path = case_dir / "manifest.sha256"

    if not manifest_path.exists() or not manifest_h_path.exists():
        print("MISSING manifest.json or manifest.sha256")
        return False

    with open(manifest_h_path, "r", encoding="utf-8") as f:
        expected_manifest_h = f.read().strip()

    actual_manifest_h = sha256_chunked(manifest_path)
    if actual_manifest_h != expected_manifest_h:
        print(
            f"TAMPERED manifest.json expected={expected_manifest_h} actual={actual_manifest_h}"
        )
        return False

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    conn = db.connect(case_dir)
    try:
        # Count mismatch check
        manifest_count = len(manifest.get("items", []))
        db_count = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        if manifest_count != db_count:
            print(
                f"MISMATCH manifest lists {manifest_count} items but DB has {db_count} evidence rows"
            )
            return False

        all_ok = True
        for item in manifest["items"]:
            stored_path = case_dir / item["stored_path"]
            if not stored_path.exists():
                print(f"MISSING {item['stored_path']}")
                all_ok = False
                continue

            actual_h = sha256_chunked(stored_path)
            expected_h = item["sha256"]

            if actual_h != expected_h:
                print(
                    f"TAMPERED {item['stored_path']} expected={expected_h} actual={actual_h}"
                )
                all_ok = False
                continue

            row = conn.execute(
                "SELECT sha256 FROM evidence WHERE id = ?", (item["id"],)
            ).fetchone()
            if not row:
                print(f"MISSING DB row for evidence id {item['id']}")
                all_ok = False
                continue

            if row["sha256"] != expected_h:
                print(
                    f"TAMPERED DB row for evidence id {item['id']} "
                    f"expected={expected_h} actual={row['sha256']}"
                )
                all_ok = False
                continue

            print(f"OK {item['stored_path']}")

        return all_ok
    finally:
        conn.close()
