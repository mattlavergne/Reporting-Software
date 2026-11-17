import hashlib
import hmac
import secrets
import time


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${h.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, salt, h = stored.split("$")
        cand = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
        return hmac.compare_digest(cand, bytes.fromhex(h))
    except Exception:
        return False


class LoginThrottle:
    """Lock a (username, ip) pair after repeated failures. In-memory, per process."""

    def __init__(self, max_fail=5, window=300):
        self.max_fail, self.window, self.fails = max_fail, window, {}

    def blocked(self, key) -> bool:
        t = [x for x in self.fails.get(key, []) if time.time() - x < self.window]
        self.fails[key] = t
        return len(t) >= self.max_fail

    def fail(self, key):
        self.fails.setdefault(key, []).append(time.time())

    def ok(self, key):
        self.fails.pop(key, None)
