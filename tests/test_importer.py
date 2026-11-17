from rtag.config import Config
from rtag.importer import import_folder
from rtag.models import Connection, Report, make_session_factory


def setup(tmp_path):
    cfg = Config(data_dir=tmp_path / "data", scheduler_enabled=False, secret="x")
    SF = make_session_factory(cfg.db_url)
    with SF() as s:
        s.add(Connection(name="main", url="sqlite://"))
        s.commit()
    src = tmp_path / "legacy"
    (src / "Finance" / "Monthly").mkdir(parents=True)
    (src / "HR").mkdir()
    (src / "Finance" / "Monthly" / "Revenue.rpt").write_bytes(b"RPT1")
    (src / "HR" / "Revenue.rpt").write_bytes(b"RPT2")  # same name, other folder
    (src / "HR" / "Headcount.sql").write_text("select 1 as n")
    (src / "HR" / "Bad.sql").write_text("delete from people")
    (src / "notes.txt").write_text("ignored")
    return cfg, SF, src


def test_import_and_rerun(tmp_path):
    cfg, SF, src = setup(tmp_path)
    sm = import_folder(cfg, SF, src, connection="main", dry_run=True)
    assert len(sm.created) == 3 and len(sm.failed) == 1
    with SF() as s:
        assert s.query(Report).count() == 0  # dry run wrote nothing

    sm = import_folder(cfg, SF, src, connection="main")
    assert len(sm.created) == 3 and sm.failed[0][0].endswith("Bad.sql")
    with SF() as s:
        names = {r.name: r for r in s.query(Report)}
        assert set(names) == {"Revenue", "HR/Revenue", "Headcount"}
        assert names["Revenue"].category == "Finance/Monthly"
        assert open(names["HR/Revenue"].latest.stored_path, "rb").read() == b"RPT2"

    sm = import_folder(cfg, SF, src, connection="main")  # nothing changed
    assert len(sm.skipped) == 3 and not sm.created and not sm.updated

    (src / "HR" / "Revenue.rpt").write_bytes(b"RPT2-edited")
    sm = import_folder(cfg, SF, src, connection="main")
    assert sm.updated == ["HR/Revenue.rpt"]
    with SF() as s:
        r = s.query(Report).filter_by(name="HR/Revenue").one()
        assert r.latest.number == 2 and r.versions[1].stored_path != r.latest.stored_path


def test_manifest_overrides(tmp_path):
    cfg, SF, src = setup(tmp_path)
    man = tmp_path / "m.csv"
    man.write_text("path,name,category,description,params,connection\n"
                   "Finance/Monthly/Revenue.rpt,Monthly Revenue,Finance,Board pack,year|Year|2025; month|Month|1,\n")
    import_folder(cfg, SF, src, connection="main", manifest=man)
    with SF() as s:
        r = s.query(Report).filter_by(name="Monthly Revenue").one()
        assert r.category == "Finance" and [p["name"] for p in r.params] == ["year", "month"]
