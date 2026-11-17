import re
import sqlite3
import sys

import pytest
from fastapi.testclient import TestClient

from rtag import engine
from rtag.app import create_app
from rtag.config import Config
from rtag.models import Job, Run, User
from rtag.security import hash_password
from rtag import service


@pytest.fixture
def env(tmp_path):
    src = tmp_path / "src.db"
    c = sqlite3.connect(src)
    c.execute("create table sales(region text, amount real, sold text)")
    c.executemany("insert into sales values(?,?,?)",
                  [("east", 10, "2025-01-05"), ("west", 20, "2025-02-01"), ("east", 5, "2025-03-01"),
                   ("=cmd()", 1, "2025-03-02")])
    c.commit()
    c.close()
    fake = tmp_path / "fake_crystal.py"
    fake.write_text("import sys\nrpt,fmt,out,*p=sys.argv[1:]\n"
                    "open(out,'w').write('PARAMS:'+','.join(p)+' RPT:'+open(rpt).read())\n")
    cfg = Config(data_dir=tmp_path / "data", scheduler_enabled=False, secret="x" * 32,
                 delivery_root=tmp_path / "out",
                 crystal_cmd=f"{sys.executable} {fake} {{report}} {{format}} {{output}} {{params}}")
    app = create_app(cfg)
    with TestClient(app) as cl:
        yield cl, app, cfg, src


def tok(cl, path="/login"):
    return re.search(r'name="csrf" value="(\w+)"', cl.get(path).text).group(1)


def login(cl, user, pw):
    return cl.post("/login", data={"username": user, "password": pw, "csrf": tok(cl)}, follow_redirects=False)


def post(cl, path, **data):
    data["csrf"] = tok(cl, "/")
    return cl.post(path, data=data, follow_redirects=False)


def admin_login(env):
    cl, app, cfg, src = env
    SF = app.state.SF
    with SF() as s:
        a = s.query(User).filter_by(username="admin").one()
        a.pw_hash = hash_password("adminpassword1")
        s.commit()
    assert login(cl, "admin", "adminpassword1").status_code == 303


def mk_sql_report(env, name="Sales"):
    cl, app, cfg, src = env
    post(cl, "/admin/connections", name="src", url=f"sqlite:///{src}")
    r = post(cl, "/reports", name=name, kind="sql", connection_id="1", category="Fin",
             params="region | Region | east",
             source="select region, amount from sales where region = :region order by sold", note="init")
    assert r.status_code == 303, r.text
    return int(r.headers["location"].rsplit("/", 1)[1])


def test_auth_required(env):
    cl = env[0]
    assert cl.get("/", follow_redirects=False).status_code == 303
    assert login(cl, "admin", "wrong").status_code == 200


def test_csrf_enforced(env):
    admin_login(env)
    cl = env[0]
    assert cl.post("/admin/connections", data={"name": "a", "url": "sqlite://"}).status_code == 403


def test_sql_run_params_and_formats(env):
    admin_login(env)
    cl = env[0]
    rid = mk_sql_report(env)
    r = post(cl, f"/reports/{rid}/run", fmt="csv", p_region="west")
    assert r.status_code == 303
    body = cl.get(r.headers["location"]).content.decode("utf-8-sig")
    assert "west,20.0" in body and "east" not in body
    # parameter is bound, not interpolated
    r = post(cl, f"/reports/{rid}/run", fmt="csv", p_region="x' or '1'='1")
    assert "east" not in cl.get(r.headers["location"]).text
    r = post(cl, f"/reports/{rid}/run", fmt="xlsx", p_region="east")
    assert cl.get(r.headers["location"]).content[:2] == b"PK"
    r = post(cl, f"/reports/{rid}/run", fmt="html", p_region="east")
    assert "sandbox" in cl.get(r.headers["location"]).headers["content-security-policy"]


def test_csv_formula_injection_neutralised():
    out = engine.export_table(["a"], [("=cmd()",), ("-5",)], "csv").decode("utf-8-sig")
    assert "'=cmd()" in out


@pytest.mark.parametrize("sql", ["delete from sales", "select 1; drop table sales",
                                 "with x as (select 1) insert into sales select 1,1,1",
                                 "select * from sales into outfile 'x'", "pragma table_info(sales)"])
def test_readonly_guard(sql):
    with pytest.raises(engine.ReportError):
        engine.check_readonly(sql)


def test_readonly_allows_keywords_in_strings_and_comments():
    engine.check_readonly("select 'drop table x' as a -- delete\n from t")


def test_versions_and_diff(env):
    admin_login(env)
    cl = env[0]
    rid = mk_sql_report(env)
    assert post(cl, f"/reports/{rid}/versions", source="select 1", note="").status_code == 400
    assert post(cl, f"/reports/{rid}/versions", source="select region from sales", note="slim").status_code == 303
    page = cl.get(f"/reports/{rid}/diff?a=1&b=2").text
    assert "select region from sales" in page and "slim" in cl.get(f"/reports/{rid}").text
    # destructive SQL rejected at save time
    assert post(cl, f"/reports/{rid}/versions", source="delete from sales", note="x").status_code == 400


def test_crystal_upload_run_and_carry_forward(env):
    admin_login(env)
    cl, app, cfg, _ = env
    post(cl, "/reports", name="x")  # noop invalid
    t = tok(cl, "/")
    r = cl.post("/reports", data={"name": "Crys", "kind": "crystal", "csrf": t, "params": "year | Year | 2024",
                                  "note": "n"}, files={"file": ("a.rpt", b"RPTDATA")}, follow_redirects=False)
    rid = int(r.headers["location"].rsplit("/", 1)[1])
    r = post(cl, f"/reports/{rid}/run", fmt="pdf", p_year="2025")
    assert cl.get(r.headers["location"]).text == "PARAMS:year=2025 RPT:RPTDATA"
    post(cl, f"/reports/{rid}/versions", note="docs only")  # no file: carries v1's file forward
    assert "v2" in cl.get(f"/reports/{rid}").text
    bad = cl.post("/reports", data={"name": "Bad", "kind": "crystal", "csrf": t},
                  files={"file": ("evil.exe", b"x")}, follow_redirects=False)
    assert bad.status_code == 400


def test_filename_traversal_sanitised():
    assert engine.safe_name("../../etc/passwd") == "passwd"
    assert engine.safe_name("a b$.rpt") == "a_b_.rpt"


def test_viewer_permissions(env):
    admin_login(env)
    cl, app, cfg, _ = env
    rid = mk_sql_report(env)
    post(cl, "/admin/users", username="vic", password="viewerpass12", role="viewer", active="1")
    cl.post("/logout", data={"csrf": tok(cl, "/")})
    login(cl, "vic", "viewerpass12")
    assert "Sales" not in cl.get("/").text
    assert cl.get(f"/reports/{rid}").status_code == 404
    assert cl.get("/jobs").status_code == 403
    assert cl.get("/admin/users").status_code == 403
    cl.post("/logout", data={"csrf": tok(cl, "/")})
    admin_login(env)
    post(cl, f"/reports/{rid}/access", users="2")
    cl.post("/logout", data={"csrf": tok(cl, "/")})
    login(cl, "vic", "viewerpass12")
    assert "Sales" in cl.get("/").text
    r = post(cl, f"/reports/{rid}/run", fmt="csv", p_region="east")
    assert r.status_code == 303
    # viewers can't edit
    assert post(cl, f"/reports/{rid}/versions", source="select 1", note="x").status_code == 403
    assert "Versions" not in cl.get(f"/reports/{rid}").text


def test_job_runs_and_delivers_to_folder(env):
    admin_login(env)
    cl, app, cfg, _ = env
    rid = mk_sql_report(env)
    assert post(cl, "/jobs", name="j", report_id=str(rid), fmt="csv", cron="nonsense").status_code == 400
    assert post(cl, "/jobs", name="j", report_id=str(rid), fmt="csv", folder="../../etc").status_code == 400
    assert post(cl, "/jobs", name="j", report_id=str(rid), fmt="csv", cron="0 6 * * 1-5",
                folder="fin/daily").status_code == 303
    run = service.run_job(cfg, app.state.SF, 1)
    assert run.status == "ok", run.message
    assert list((cfg.delivery_root / "fin" / "daily").glob("*.csv"))


def test_job_failure_recorded(env):
    admin_login(env)
    cl, app, cfg, _ = env
    rid = mk_sql_report(env)
    post(cl, "/jobs", name="j", report_id=str(rid), fmt="csv", emails="a@b.c")  # SMTP not configured
    run = service.run_job(cfg, app.state.SF, 1)
    assert run.status == "error" and "SMTP" in run.message


def test_scheduler_registers_cron(env, tmp_path):
    cl, app, cfg, _ = env
    admin_login(env)
    rid = mk_sql_report(env)
    post(cl, "/jobs", name="j", report_id=str(rid), fmt="csv", cron="0 6 * * 1-5")
    with app.state.SF() as s:
        j = s.get(Job, 1)
    sch = app.state.sched
    sch.sched.start(paused=True)
    sch.sync(j)
    assert sch.sched.get_job("job1") is not None
    sch.stop()


def test_bad_sql_error_is_recorded_not_500(env):
    admin_login(env)
    cl = env[0]
    rid = mk_sql_report(env)
    post(cl, f"/reports/{rid}/versions", source="select nope from missing where a=:region", note="broken")
    r = post(cl, f"/reports/{rid}/run", fmt="csv", p_region="e")
    assert r.status_code == 200 and "Database error" in r.text
