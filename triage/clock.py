from datetime import datetime, timezone
import time


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def now_ts() -> int:
    return int(time.time())
