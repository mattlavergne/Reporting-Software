import os
import secrets
from pathlib import Path


class Config:
    """All settings come from environment variables (prefix RTAG_)."""

    def __init__(self, **over):
        e = os.environ.get
        self.data_dir = Path(over.get("data_dir") or e("RTAG_DATA_DIR", "./data")).resolve()
        self.db_url = over.get("db_url") or e("RTAG_DB_URL") or f"sqlite:///{self.data_dir}/rtag.db"
        self.files_dir = self.data_dir / "files"
        self.runs_dir = self.data_dir / "runs"
        # Delivery to network folders is confined to this root.
        self.delivery_root = Path(over.get("delivery_root") or e("RTAG_DELIVERY_ROOT", self.data_dir / "delivered")).resolve()
        self.smtp_host = over.get("smtp_host") or e("RTAG_SMTP_HOST", "")
        self.smtp_port = int(e("RTAG_SMTP_PORT", "25"))
        self.smtp_user = e("RTAG_SMTP_USER", "")
        self.smtp_pass = e("RTAG_SMTP_PASS", "")
        self.smtp_from = e("RTAG_SMTP_FROM", "reports@localhost")
        self.smtp_starttls = e("RTAG_SMTP_STARTTLS", "0") == "1"
        # Crystal: command template, e.g.  CrystalExport.exe {report} {format} {output} {params}
        self.crystal_cmd = over.get("crystal_cmd") or e("RTAG_CRYSTAL_CMD", "")
        self.crystal_timeout = int(e("RTAG_CRYSTAL_TIMEOUT", "600"))
        # SSRS: e.g. http://server/ReportServer
        self.ssrs_url = over.get("ssrs_url") or e("RTAG_SSRS_URL", "")
        self.ssrs_user = e("RTAG_SSRS_USER", "")
        self.ssrs_pass = e("RTAG_SSRS_PASS", "")
        self.max_upload = int(e("RTAG_MAX_UPLOAD_MB", "50")) * 1024 * 1024
        self.max_rows = int(e("RTAG_MAX_ROWS", "500000"))
        self.https_only = e("RTAG_HTTPS_ONLY", "0") == "1"
        self.scheduler_enabled = over.get("scheduler_enabled", e("RTAG_SCHEDULER", "1") == "1")
        for d in (self.data_dir, self.files_dir, self.runs_dir):
            d.mkdir(parents=True, exist_ok=True)
        self._secret = over.get("secret") or e("RTAG_SECRET")

    @property
    def secret(self) -> str:
        if self._secret:
            return self._secret
        f = self.data_dir / ".secret"
        if not f.exists():
            f.write_text(secrets.token_hex(32))
            f.chmod(0o600)
        return f.read_text().strip()
