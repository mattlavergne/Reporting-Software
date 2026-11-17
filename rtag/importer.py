"""Bulk import of existing reports from a folder tree.

    python -m rtag.importer <folder> [--connection NAME] [--manifest file.csv] [--dry-run]

- *.rpt  -> Crystal report (file stored as a version)
- *.sql  -> SQL report (needs --connection or a manifest `connection` column)
- Category defaults to the sub-folder path, e.g. Finance/Monthly.
- Optional manifest CSV (columns: path,name,category,description,params,connection);
  `path` is relative to <folder>; `params` uses "name|label|default; name2|label2|default2".
- Re-runnable: unchanged files are skipped; changed files become a new version.
"""
import argparse
import csv
import json
import hashlib
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select

from . import engine
from .config import Config
from .models import Connection, Note, Report, User, Version, make_session_factory


@dataclass
class Summary:
    created: list = field(default_factory=list)
    updated: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    failed: list = field(default_factory=list)  # (path, reason)


def _params(txt: str) -> list[dict]:
    out = []
    for item in filter(None, (x.strip() for x in (txt or "").split(";"))):
        p = [x.strip() for x in item.split("|")]
        out.append({"name": p[0], "label": p[1] if len(p) > 1 and p[1] else p[0],
                    "default": p[2] if len(p) > 2 else ""})
    return out


def import_folder(cfg: Config, SF, root: Path, connection: str = "", manifest: Path | None = None,
                  dry_run: bool = False, author: str = "import") -> Summary:
    root = root.resolve()
    meta = {}
    if manifest:
        with open(manifest, newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                meta[str(Path(row["path"]))] = row
    files = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in (".rpt", ".sql"))
    sm = Summary()
    with SF() as s:
        conns = {c.name: c for c in s.scalars(select(Connection))}
        owner = s.scalar(select(User).where(User.role == "admin"))
        used_names = {}
        for path in files:
            rel = str(path.relative_to(root))
            m = meta.get(rel, {})
            kind = "crystal" if path.suffix.lower() == ".rpt" else "sql"
            category = m.get("category") or str(Path(rel).parent).replace("\\", "/").replace(".", "")
            name = (m.get("name") or path.stem).strip()
            # Same file name in two folders: disambiguate with the folder path.
            if name in used_names and used_names[name] != rel:
                name = f"{category}/{name}" if category else rel
            used_names[name] = rel
            try:
                data = path.read_bytes()
                sha = hashlib.sha256(data).hexdigest()
                conn = None
                source = ""
                if kind == "sql":
                    source = data.decode("utf-8-sig").strip()
                    engine.check_readonly(source)
                    cname = m.get("connection") or connection
                    conn = conns.get(cname)
                    if not conn:
                        raise engine.ReportError(f"connection {cname!r} not found (create it first)")
                r = s.scalar(select(Report).where(Report.name == name))
                if r and r.kind != kind:
                    raise engine.ReportError(f"existing report {name!r} is type {r.kind}")
                if r and r.latest and r.latest.sha256 == sha:
                    sm.skipped.append(rel)
                    continue
                if dry_run:
                    (sm.updated if r else sm.created).append(rel)
                    continue
                if not r:
                    r = Report(name=name, kind=kind, category=category, description=m.get("description", ""),
                               params_json=json.dumps(_params(m.get("params", ""))),
                               connection_id=conn.id if conn else None, owner_id=owner.id if owner else None)
                    s.add(r)
                    s.flush()
                    s.add(Note(report_id=r.id, text=f"Imported from {path}", author=author))
                    bucket = sm.created
                else:
                    bucket = sm.updated
                num = (r.latest.number if r.latest else 0) + 1
                v = Version(report_id=r.id, number=num, source=source, sha256=sha, author=author,
                            note="Imported" if num == 1 else f"Re-imported (file changed): {path}")
                if kind == "crystal":
                    d = cfg.files_dir / str(r.id)
                    d.mkdir(parents=True, exist_ok=True)
                    fn = engine.safe_name(path.name)
                    dest = d / f"v{num}_{fn}"
                    shutil.copyfile(path, dest)
                    v.filename, v.stored_path = fn, str(dest)
                s.add(v)
                s.commit()
                bucket.append(rel)
            except Exception as e:
                s.rollback()
                sm.failed.append((rel, str(e)))
    return sm


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", type=Path)
    ap.add_argument("--connection", default="", help="connection name for .sql files")
    ap.add_argument("--manifest", type=Path)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    cfg = Config(scheduler_enabled=False)
    sm = import_folder(cfg, make_session_factory(cfg.db_url), a.folder, a.connection, a.manifest, a.dry_run)
    tag = "would be " if a.dry_run else ""
    print(f"{len(sm.created)} {tag}created, {len(sm.updated)} {tag}updated, "
          f"{len(sm.skipped)} unchanged, {len(sm.failed)} failed")
    for rel, why in sm.failed:
        print(f"  FAILED {rel}: {why}")
    return 1 if sm.failed else 0


if __name__ == "__main__":
    sys.exit(main())
