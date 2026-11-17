import datetime as dt
import json

from sqlalchemy import (Boolean, DateTime, ForeignKey, Integer, String, Text,
                        UniqueConstraint, create_engine)
from sqlalchemy.orm import (DeclarativeBase, Mapped, mapped_column, relationship,
                            sessionmaker)

ROLES = ("admin", "editor", "viewer")
KINDS = ("sql", "crystal", "ssrs")


def now():
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    pw_hash: Mapped[str] = mapped_column(String(300))
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    email: Mapped[str] = mapped_column(String(200), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Connection(Base):
    """Named database connection used by SQL reports. URL may contain ${ENV_VAR}."""
    __tablename__ = "connections"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    url: Mapped[str] = mapped_column(String(500))


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(100), default="")
    kind: Mapped[str] = mapped_column(String(16))
    connection_id: Mapped[int | None] = mapped_column(ForeignKey("connections.id"), nullable=True)
    params_json: Mapped[str] = mapped_column(Text, default="[]")  # [{name,label,default}]
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
    versions: Mapped[list["Version"]] = relationship(
        back_populates="report", order_by="Version.number.desc()", cascade="all, delete-orphan")
    notes: Mapped[list["Note"]] = relationship(
        order_by="Note.created.desc()", cascade="all, delete-orphan")
    connection: Mapped["Connection | None"] = relationship()

    @property
    def params(self) -> list[dict]:
        return json.loads(self.params_json or "[]")

    @property
    def latest(self) -> "Version | None":
        return self.versions[0] if self.versions else None


class Version(Base):
    """Immutable snapshot. SQL/SSRS: `source` holds query text or report path.
    Crystal: `filename`/`stored_path` hold the uploaded .rpt."""
    __tablename__ = "versions"
    __table_args__ = (UniqueConstraint("report_id", "number"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"))
    number: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(Text, default="")
    filename: Mapped[str] = mapped_column(String(300), default="")
    stored_path: Mapped[str] = mapped_column(String(600), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    author: Mapped[str] = mapped_column(String(80), default="")
    created: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
    report: Mapped[Report] = relationship(back_populates="versions")


class Note(Base):
    __tablename__ = "notes"
    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"))
    text: Mapped[str] = mapped_column(Text)
    author: Mapped[str] = mapped_column(String(80))
    created: Mapped[dt.datetime] = mapped_column(DateTime, default=now)


class Grant(Base):
    """Lets a viewer run a specific report."""
    __tablename__ = "grants"
    __table_args__ = (UniqueConstraint("report_id", "user_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"))
    params_json: Mapped[str] = mapped_column(Text, default="{}")
    fmt: Mapped[str] = mapped_column(String(10), default="xlsx")
    cron: Mapped[str] = mapped_column(String(100), default="")  # 5-field cron; blank = manual only
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    emails: Mapped[str] = mapped_column(Text, default="")  # comma separated
    folder: Mapped[str] = mapped_column(String(300), default="")  # relative to delivery root
    created_by: Mapped[str] = mapped_column(String(80), default="")
    report: Mapped[Report] = relationship()

    @property
    def params(self) -> dict:
        return json.loads(self.params_json or "{}")


class Run(Base):
    __tablename__ = "runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"))
    job_id: Mapped[int | None] = mapped_column(ForeignKey("jobs.id"), nullable=True)
    version_number: Mapped[int] = mapped_column(Integer, default=0)
    fmt: Mapped[str] = mapped_column(String(10), default="")
    status: Mapped[str] = mapped_column(String(12), default="running")  # running/ok/error
    started: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
    finished: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    rows: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_path: Mapped[str] = mapped_column(String(600), default="")
    output_name: Mapped[str] = mapped_column(String(300), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    triggered_by: Mapped[str] = mapped_column(String(80), default="")
    report: Mapped[Report] = relationship()
    job: Mapped["Job | None"] = relationship()


def make_session_factory(url: str):
    kw = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
    engine = create_engine(url, **kw)
    Base.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)
