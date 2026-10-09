import pytest
import tempfile
import json
import os
from pathlib import Path
from forensic import ingest, db

def test_ingest_basic():
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        case_dir = tdp / "cases" / "s1"
        src_dir = tdp / "src"
        src_dir.mkdir(parents=True)
        
        auth_log = src_dir / "auth.log"
        auth_log.write_text("dummy log content\n")
        
        sources_json = src_dir / "sources.json"
        sources_json.write_text(json.dumps({
            "case_id": "s1",
            "sources": [
                {"path": "auth.log", "host": "web01", "source_type": "auth_log", "declared_tz": "UTC"}
            ]
        }))
        
        ingest.ingest(case_dir, sources_json, "test_collector")
        
        assert (case_dir / "evidence" / "web01__auth.log").exists()
        assert (case_dir / "manifest.json").exists()
        assert (case_dir / "manifest.sha256").exists()
        
        assert ingest.verify(case_dir) == True
        
        # Test tamper
        (case_dir / "evidence" / "web01__auth.log").chmod(0o666)
        (case_dir / "evidence" / "web01__auth.log").write_text("tampered\n")
        assert ingest.verify(case_dir) == False
