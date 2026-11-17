import difflib
import hashlib
import html
import json
import logging
import re
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from starlette.middleware.sessions import SessionMiddleware

from . import engine, service
from .config import Config
from .models import (KINDS, ROLES, Connection, Grant, Job, Note, Report, Run, User,
                     Version, make_session_factory)
from .security import LoginThrottle, hash_password, verify_password

HERE = Path(__file__).parent
log = logging.getLogger("rtag")


class LoginRequired(Exception):
    pass


def parse_params(txt: str) -> list[dict]:
    """One per line: name | label | default"""
    out = []
    for line in txt.splitlines():
        if not line.strip():
            continue
        parts = [x.strip() for x in line.split("|")]
        if not re.fullmatch(r"[A-Za-z_]\w*", parts[0]):
            raise HTTPException(400, f"Bad parameter name: {parts[0]!r}")
        out.append({"name": parts[0], "label": parts[1] if len(parts) > 1 and parts[1] else parts[0],
                    "default": parts[2] if len(parts) > 2 else ""})
    return out


def create_app(cfg: Config | None = None) -> FastAPI:
    cfg = cfg or Config()
    SF = make_session_factory(cfg.db_url)
    sched = service.Scheduler(cfg, SF)
    throttle = LoginThrottle()

    with SF() as s:
        if not s.scalar(select(func.count()).select_from(User)):
            pw = secrets.token_urlsafe(12)
            s.add(User(username="admin", pw_hash=hash_password(pw), role="admin"))
            s.commit()
            print(f"\n*** First start: created user 'admin' with password: {pw}\n    Change it under Admin > Users.\n")

    @asynccontextmanager
    async def lifespan(app):
        sched.start()
        yield
        sched.stop()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SessionMiddleware, secret_key=cfg.secret, same_site="lax",
                       https_only=cfg.https_only, max_age=60 * 60 * 12)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    T = Jinja2Templates(directory=HERE / "templates")
    app.state.cfg, app.state.SF, app.state.sched = cfg, SF, sched

    # ------------------------------------------------------------ helpers
    def db():
        with SF() as s:
            yield s

    def render(request, name, user=None, **ctx):
        if "csrf" not in request.session:
            request.session["csrf"] = secrets.token_hex(16)
        ctx.update(user=user, csrf=request.session["csrf"], kinds=KINDS, roles=ROLES,
                   formats=list(engine.FORMATS), table_formats=engine.TABLE_FORMATS)
        return T.TemplateResponse(request, name, ctx)

    def current_user(request: Request, s=Depends(db)) -> User:
        uid = request.session.get("uid")
        u = s.get(User, uid) if uid else None
        if not u or not u.active:
            raise LoginRequired()
        return u

    def editor(u: User = Depends(current_user)) -> User:
        if u.role not in ("admin", "editor"):
            raise HTTPException(403, "Editor role required")
        return u

    def admin(u: User = Depends(current_user)) -> User:
        if u.role != "admin":
            raise HTTPException(403, "Admin role required")
        return u

    async def csrf(request: Request):
        if request.method == "POST":
            form = await request.form()
            tok = request.session.get("csrf")
            if not tok or not secrets.compare_digest(str(form.get("csrf", "")), tok):
                raise HTTPException(403, "Bad CSRF token")

    def can_run(s, u: User, rid: int) -> bool:
        if u.role in ("admin", "editor"):
            return True
        return s.scalar(select(Grant.id).where(Grant.report_id == rid, Grant.user_id == u.id)) is not None

    def get_report(s, u, rid, need_run=True) -> Report:
        r = s.get(Report, rid)
        if not r or (need_run and not can_run(s, u, rid)):
            raise HTTPException(404, "Report not found")
        return r

    @app.exception_handler(LoginRequired)
    async def _login_redirect(request, exc):
        return RedirectResponse("/login", 303)

    @app.exception_handler(HTTPException)
    async def _http_err(request, exc):
        return HTMLResponse(f"<link rel=stylesheet href=/static/style.css><main><h2>{exc.status_code}</h2>"
                            f"<p>{html.escape(str(exc.detail))}</p><a href=/>Home</a></main>",
                            status_code=exc.status_code)

    # ------------------------------------------------------------ auth
    @app.get("/login")
    def login_page(request: Request):
        return render(request, "login.html", error=None)

    @app.post("/login", dependencies=[Depends(csrf)])
    def login(request: Request, username: str = Form(), password: str = Form(), s=Depends(db)):
        key = (username.lower(), request.client.host if request.client else "")
        if throttle.blocked(key):
            return render(request, "login.html", error="Too many attempts. Try again in a few minutes.")
        u = s.scalar(select(User).where(User.username == username))
        if u and u.active and verify_password(password, u.pw_hash):
            throttle.ok(key)
            request.session.clear()
            request.session["uid"] = u.id
            return RedirectResponse("/", 303)
        throttle.fail(key)
        return render(request, "login.html", error="Invalid credentials")

    @app.post("/logout", dependencies=[Depends(csrf)])
    def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/login", 303)

    # ------------------------------------------------------------ reports
    @app.get("/")
    def index(request: Request, q: str = "", category: str = "", u=Depends(current_user), s=Depends(db)):
        stmt = select(Report).order_by(Report.category, Report.name)
        if q:
            like = f"%{q}%"
            stmt = stmt.where(Report.name.ilike(like) | Report.description.ilike(like))
        if category:
            stmt = stmt.where(Report.category == category)
        reports = [r for r in s.scalars(stmt) if can_run(s, u, r.id)]
        cats = sorted({c for c in s.scalars(select(Report.category)) if c})
        return render(request, "index.html", u, reports=reports, q=q, category=category, cats=cats)

    @app.get("/reports/new")
    def new_form(request: Request, u=Depends(editor), s=Depends(db)):
        return render(request, "report_new.html", u, conns=s.scalars(select(Connection)).all())

    @app.post("/reports", dependencies=[Depends(csrf)])
    async def create_report(request: Request, name: str = Form(), kind: str = Form(),
                            category: str = Form(""), description: str = Form(""),
                            connection_id: int | None = Form(None), params: str = Form(""),
                            source: str = Form(""), note: str = Form("Initial version"),
                            file: UploadFile | None = None, u=Depends(editor), s=Depends(db)):
        if kind not in KINDS:
            raise HTTPException(400, "Bad kind")
        if s.scalar(select(Report.id).where(Report.name == name.strip())) or not name.strip():
            raise HTTPException(400, "A report with that name already exists (or name is empty)")
        r = Report(name=name.strip(), kind=kind, category=category.strip(), description=description,
                   connection_id=connection_id if kind == "sql" else None,
                   params_json=json.dumps(parse_params(params)), owner_id=u.id)
        s.add(r)
        s.flush()
        await add_version(s, r, u, source, note, file)
        s.commit()
        return RedirectResponse(f"/reports/{r.id}", 303)

    async def add_version(s, r: Report, u: User, source: str, note: str, file: UploadFile | None):
        prev = r.latest
        num = (prev.number if prev else 0) + 1
        v = Version(report_id=r.id, number=num, source=source.strip(), note=note, author=u.username)
        if r.kind == "sql":
            if not v.source:
                raise HTTPException(400, "SQL required")
            try:
                engine.check_readonly(v.source)
            except engine.ReportError as e:
                raise HTTPException(400, str(e))
        if r.kind == "ssrs" and not v.source:
            raise HTTPException(400, "SSRS report path required, e.g. %2fSales%2fMonthly")
        if file is not None and file.filename:
            if r.kind != "crystal" or not file.filename.lower().endswith(".rpt"):
                raise HTTPException(400, "Only .rpt files can be uploaded, for Crystal reports")
            data = await file.read(cfg.max_upload + 1)
            if len(data) > cfg.max_upload:
                raise HTTPException(413, "File too large")
            d = cfg.files_dir / str(r.id)
            d.mkdir(parents=True, exist_ok=True)
            fn = engine.safe_name(file.filename)
            path = d / f"v{num}_{fn}"
            path.write_bytes(data)
            v.filename, v.stored_path, v.sha256 = fn, str(path), hashlib.sha256(data).hexdigest()
        elif prev and r.kind == "crystal":  # carry the file forward (e.g. only notes/params changed)
            v.filename, v.stored_path, v.sha256 = prev.filename, prev.stored_path, prev.sha256
        elif r.kind == "crystal":
            raise HTTPException(400, "Upload a .rpt file")
        s.add(v)

    @app.get("/reports/{rid}")
    def report_page(request: Request, rid: int, u=Depends(current_user), s=Depends(db)):
        r = get_report(s, u, rid)
        jobs = s.scalars(select(Job).where(Job.report_id == rid)).all() if u.role != "viewer" else []
        runs = s.scalars(select(Run).where(Run.report_id == rid).order_by(Run.id.desc()).limit(15)).all()
        if u.role == "viewer":
            runs = [x for x in runs if x.triggered_by == u.username]
        extra = {}
        if u.role == "admin":
            granted = {g.user_id for g in s.scalars(select(Grant).where(Grant.report_id == rid))}
            extra = dict(viewers=s.scalars(select(User).where(User.role == "viewer")).all(), granted=granted)
        return render(request, "report.html", u, r=r, jobs=jobs, runs=runs,
                      conns=s.scalars(select(Connection)).all(), **extra)

    @app.post("/reports/{rid}/settings", dependencies=[Depends(csrf)])
    def settings(rid: int, name: str = Form(), category: str = Form(""), description: str = Form(""),
                 params: str = Form(""), connection_id: int | None = Form(None),
                 u=Depends(editor), s=Depends(db)):
        r = get_report(s, u, rid, False)
        clash = s.scalar(select(Report.id).where(Report.name == name.strip(), Report.id != rid))
        if clash or not name.strip():
            raise HTTPException(400, "Name empty or already used")
        r.name, r.category, r.description = name.strip(), category.strip(), description
        r.params_json = json.dumps(parse_params(params))
        if r.kind == "sql":
            r.connection_id = connection_id
        s.commit()
        return RedirectResponse(f"/reports/{rid}", 303)

    @app.post("/reports/{rid}/versions", dependencies=[Depends(csrf)])
    async def new_version(rid: int, source: str = Form(""), note: str = Form(""),
                          file: UploadFile | None = None, u=Depends(editor), s=Depends(db)):
        r = get_report(s, u, rid, False)
        if not note.strip():
            raise HTTPException(400, "A change note is required")
        await add_version(s, r, u, source, note.strip(), file)
        s.commit()
        return RedirectResponse(f"/reports/{rid}", 303)

    @app.get("/reports/{rid}/diff")
    def diff(request: Request, rid: int, a: int, b: int, u=Depends(editor), s=Depends(db)):
        r = get_report(s, u, rid, False)
        va = next((v for v in r.versions if v.number == a), None)
        vb = next((v for v in r.versions if v.number == b), None)
        if not va or not vb:
            raise HTTPException(404, "Version not found")
        lines = list(difflib.unified_diff(va.source.splitlines(), vb.source.splitlines(),
                                          f"v{a}", f"v{b}", lineterm=""))
        file_changed = va.sha256 != vb.sha256
        return render(request, "diff.html", u, r=r, a=va, b=vb, lines=lines, file_changed=file_changed)

    @app.get("/reports/{rid}/versions/{num}/file")
    def version_file(rid: int, num: int, u=Depends(editor), s=Depends(db)):
        r = get_report(s, u, rid, False)
        v = next((v for v in r.versions if v.number == num), None)
        if not v or not v.stored_path or not Path(v.stored_path).exists():
            raise HTTPException(404, "No file")
        return FileResponse(v.stored_path, filename=v.filename)

    @app.post("/reports/{rid}/notes", dependencies=[Depends(csrf)])
    def add_note(rid: int, text: str = Form(), u=Depends(editor), s=Depends(db)):
        get_report(s, u, rid, False)
        if text.strip():
            s.add(Note(report_id=rid, text=text.strip(), author=u.username))
            s.commit()
        return RedirectResponse(f"/reports/{rid}", 303)

    @app.post("/reports/{rid}/delete", dependencies=[Depends(csrf)])
    def delete_report(rid: int, u=Depends(admin), s=Depends(db)):
        r = get_report(s, u, rid, False)
        for j in s.scalars(select(Job).where(Job.report_id == rid)):
            sched.remove(j.id)
            for run in s.scalars(select(Run).where(Run.job_id == j.id)):
                run.job_id = None
            s.delete(j)
        for g in s.scalars(select(Grant).where(Grant.report_id == rid)):
            s.delete(g)
        s.delete(r)
        s.commit()
        return RedirectResponse("/", 303)

    @app.post("/reports/{rid}/access", dependencies=[Depends(csrf)])
    async def set_access(request: Request, rid: int, u=Depends(admin), s=Depends(db)):
        get_report(s, u, rid, False)
        ids = {int(x) for x in (await request.form()).getlist("users") if str(x).isdigit()}
        for g in s.scalars(select(Grant).where(Grant.report_id == rid)):
            s.delete(g)
        s.flush()
        for uid in ids:
            s.add(Grant(report_id=rid, user_id=uid))
        s.commit()
        return RedirectResponse(f"/reports/{rid}", 303)

    # ------------------------------------------------------------ running
    @app.post("/reports/{rid}/run", dependencies=[Depends(csrf)])
    async def run_now(request: Request, rid: int, fmt: str = Form("xlsx"), u=Depends(current_user),
                      s=Depends(db)):
        r = get_report(s, u, rid)
        form = await request.form()
        params = {p["name"]: str(form.get(f"p_{p['name']}", p["default"])) for p in r.params}
        run = service.run_report(cfg, SF, rid, params, fmt, u.username)
        if run.status != "ok":
            return render(request, "run_error.html", u, r=r, run=run)
        return RedirectResponse(f"/runs/{run.id}/download" + ("?inline=1" if fmt == "html" else ""), 303)

    @app.get("/runs")
    def runs_page(request: Request, u=Depends(current_user), s=Depends(db)):
        stmt = select(Run).order_by(Run.id.desc()).limit(200)
        if u.role == "viewer":
            stmt = stmt.where(Run.triggered_by == u.username)
        return render(request, "runs.html", u, runs=s.scalars(stmt).all())

    @app.get("/runs/{run_id}/download")
    def download(run_id: int, inline: int = 0, u=Depends(current_user), s=Depends(db)):
        run = s.get(Run, run_id)
        if not run or not can_run(s, u, run.report_id) or run.status == "error" and not run.output_path:
            raise HTTPException(404, "Run not found")
        if u.role == "viewer" and run.triggered_by != u.username:
            raise HTTPException(404, "Run not found")
        p = Path(run.output_path)
        if not run.output_path or not p.exists():
            raise HTTPException(404, "Output no longer available")
        ext = p.suffix.lstrip(".")
        if inline and ext == "html":  # sandboxed: generated HTML must not run script in our origin
            return Response(p.read_bytes(), media_type="text/html; charset=utf-8",
                            headers={"Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'"})
        return FileResponse(p, filename=run.output_name, media_type=engine.FORMATS.get(ext))

    # ------------------------------------------------------------ jobs
    @app.get("/jobs")
    def jobs_page(request: Request, u=Depends(editor), s=Depends(db)):
        return render(request, "jobs.html", u, jobs=s.scalars(select(Job).order_by(Job.name)).all(),
                      reports=s.scalars(select(Report).order_by(Report.name)).all(),
                      next_runs={j.id: (sched.sched.get_job(f"job{j.id}").next_run_time
                                        if sched.sched.get_job(f"job{j.id}") else None)
                                 for j in s.scalars(select(Job))})

    @app.post("/jobs", dependencies=[Depends(csrf)])
    async def create_job(request: Request, name: str = Form(), report_id: int = Form(),
                         fmt: str = Form("xlsx"), cron: str = Form(""), emails: str = Form(""),
                         folder: str = Form(""), u=Depends(editor), s=Depends(db)):
        r = get_report(s, u, report_id)
        form = await request.form()
        if cron.strip() and not service.valid_cron(cron):
            raise HTTPException(400, "Invalid cron expression (5 fields, e.g. '0 6 * * 1-5')")
        if fmt not in engine.FORMATS or (r.kind == "sql" and fmt not in engine.TABLE_FORMATS):
            raise HTTPException(400, "Format not supported for this report")
        if folder:
            dest = (cfg.delivery_root / folder).resolve()
            if dest != cfg.delivery_root and cfg.delivery_root not in dest.parents:
                raise HTTPException(400, "Folder must be inside the delivery root")
        params = {p["name"]: str(form.get(f"p_{p['name']}", p["default"])) for p in r.params}
        j = Job(name=name.strip(), report_id=report_id, params_json=json.dumps(params), fmt=fmt,
                cron=cron.strip(), emails=emails, folder=folder.strip(), created_by=u.username)
        s.add(j)
        s.commit()
        sched.sync(j)
        return RedirectResponse("/jobs", 303)

    def _job(s, jid) -> Job:
        j = s.get(Job, jid)
        if not j:
            raise HTTPException(404, "Job not found")
        return j

    @app.post("/jobs/{jid}/toggle", dependencies=[Depends(csrf)])
    def job_toggle(jid: int, u=Depends(editor), s=Depends(db)):
        j = _job(s, jid)
        j.enabled = not j.enabled
        s.commit()
        sched.sync(j)
        return RedirectResponse("/jobs", 303)

    @app.post("/jobs/{jid}/run", dependencies=[Depends(csrf)])
    def job_run(jid: int, u=Depends(editor), s=Depends(db)):
        _job(s, jid)
        service.run_job(cfg, SF, jid, who=u.username)
        return RedirectResponse("/runs", 303)

    @app.post("/jobs/{jid}/delete", dependencies=[Depends(csrf)])
    def job_delete(jid: int, u=Depends(editor), s=Depends(db)):
        j = _job(s, jid)
        sched.remove(jid)
        for run in s.scalars(select(Run).where(Run.job_id == jid)):
            run.job_id = None
        s.delete(j)
        s.commit()
        return RedirectResponse("/jobs", 303)

    # ------------------------------------------------------------ admin
    @app.get("/admin/users")
    def users_page(request: Request, u=Depends(admin), s=Depends(db)):
        return render(request, "admin_users.html", u, users=s.scalars(select(User).order_by(User.username)).all())

    @app.post("/admin/users", dependencies=[Depends(csrf)])
    def users_save(username: str = Form(), password: str = Form(""), role: str = Form("viewer"),
                   email: str = Form(""), active: str = Form(""), u=Depends(admin), s=Depends(db)):
        if role not in ROLES or not re.fullmatch(r"[\w.@-]{1,80}", username):
            raise HTTPException(400, "Bad username or role")
        t = s.scalar(select(User).where(User.username == username))
        if t is None:
            if len(password) < 10:
                raise HTTPException(400, "Password must be at least 10 characters")
            s.add(User(username=username, pw_hash=hash_password(password), role=role, email=email))
        else:
            if t.id == u.id and (role != "admin" or not active):
                raise HTTPException(400, "You cannot demote or disable yourself")
            if password:
                if len(password) < 10:
                    raise HTTPException(400, "Password must be at least 10 characters")
                t.pw_hash = hash_password(password)
            t.role, t.email, t.active = role, email, bool(active)
        s.commit()
        return RedirectResponse("/admin/users", 303)

    @app.get("/admin/connections")
    def conns_page(request: Request, u=Depends(admin), s=Depends(db)):
        return render(request, "admin_conns.html", u, conns=s.scalars(select(Connection)).all())

    @app.post("/admin/connections", dependencies=[Depends(csrf)])
    def conns_save(name: str = Form(), url: str = Form(), u=Depends(admin), s=Depends(db)):
        c = s.scalar(select(Connection).where(Connection.name == name))
        if c:
            c.url = url
        else:
            s.add(Connection(name=name, url=url))
        s.commit()
        return RedirectResponse("/admin/connections", 303)

    @app.post("/admin/connections/{cid}/delete", dependencies=[Depends(csrf)])
    def conns_delete(cid: int, u=Depends(admin), s=Depends(db)):
        if s.scalar(select(Report.id).where(Report.connection_id == cid)):
            raise HTTPException(400, "Connection is used by a report")
        c = s.get(Connection, cid)
        if c:
            s.delete(c)
            s.commit()
        return RedirectResponse("/admin/connections", 303)

    return app
