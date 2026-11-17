"""Run recording, job execution, and scheduling."""
import datetime as dt
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from . import engine
from .config import Config
from .models import Job, Run, Report, now

log = logging.getLogger("rtag")


def run_report(cfg: Config, SF, report_id: int, params: dict, fmt: str, who: str,
               job_id: int | None = None, version_number: int | None = None) -> Run:
    """Execute a report, persist output + a Run row. Never raises for report errors."""
    with SF() as s:
        report = s.get(Report, report_id)
        ver = next((v for v in report.versions if v.number == version_number), None) if version_number \
            else report.latest
        run = Run(report_id=report_id, job_id=job_id, fmt=fmt, triggered_by=who,
                  version_number=ver.number if ver else 0)
        s.add(run)
        s.commit()
        try:
            if not ver:
                raise engine.ReportError("Report has no versions")
            res = engine.execute(cfg, report, ver, params, fmt)
            stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            name = f"{engine.safe_name(report.name)}_{stamp}_r{run.id}.{res.ext}"
            path = cfg.runs_dir / name
            path.write_bytes(res.data)
            run.output_path, run.output_name, run.rows, run.status = str(path), name, res.rows, "ok"
        except engine.ReportError as e:
            run.status, run.message = "error", str(e)
        except Exception as e:  # unexpected: log details, show short message
            log.exception("run failed")
            run.status, run.message = "error", f"Internal error: {type(e).__name__}"
        run.finished = now()
        s.commit()
        return run


def run_job(cfg: Config, SF, job_id: int, who="scheduler") -> Run | None:
    with SF() as s:
        job = s.get(Job, job_id)
        if not job:
            return None
        rid, params, fmt = job.report_id, job.params, job.fmt
        emails = [e.strip() for e in job.emails.split(",") if e.strip()]
        folder, jname = job.folder, job.name
    run = run_report(cfg, SF, rid, params, fmt, who, job_id=job_id)
    if run.status != "ok":
        return run
    notes = []
    data = open(run.output_path, "rb").read()
    try:
        if folder:
            notes.append(f"saved to {engine.deliver_folder(cfg, folder, run.output_name, data)}")
        if emails:
            engine.deliver_email(cfg, emails, f"[Report] {jname}", f"Attached: {run.output_name}",
                                 run.output_name, data, fmt)
            notes.append(f"emailed {len(emails)} recipient(s)")
    except Exception as e:
        run.status = "error"
        notes.append(f"delivery failed: {e}")
    with SF() as s:
        r = s.get(Run, run.id)
        r.status, r.message = run.status, "; ".join(notes)
        s.commit()
        return r


class Scheduler:
    def __init__(self, cfg: Config, SF):
        self.cfg, self.SF = cfg, SF
        self.sched = BackgroundScheduler()

    def start(self):
        if not self.cfg.scheduler_enabled:
            return
        with self.SF() as s:
            for j in s.query(Job).all():
                self.sync(j)
        self.sched.start()

    def stop(self):
        if self.sched.running:
            self.sched.shutdown(wait=False)

    def sync(self, job: Job):
        jid = f"job{job.id}"
        if self.sched.get_job(jid):
            self.sched.remove_job(jid)
        if job.enabled and job.cron.strip():
            self.sched.add_job(run_job, CronTrigger.from_crontab(job.cron), id=jid,
                               args=[self.cfg, self.SF, job.id], max_instances=1, coalesce=True,
                               misfire_grace_time=3600)

    def remove(self, job_id: int):
        if self.sched.get_job(f"job{job_id}"):
            self.sched.remove_job(f"job{job_id}")


def valid_cron(expr: str) -> bool:
    try:
        CronTrigger.from_crontab(expr)
        return True
    except Exception:
        return False
