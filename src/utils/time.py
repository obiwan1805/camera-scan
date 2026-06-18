"""Time-formatting helpers."""
import math
from typing import Optional


def format_hms(seconds: Optional[float]) -> str:
    """Format seconds as H:MM:SS (or M:SS if under an hour).

    Returns '—' for None, negative, NaN, or inf — covers "ETA unknown".
    """
    if seconds is None or not math.isfinite(seconds) or seconds < 0:
        return "—"
    total = int(seconds)
    h, remainder = divmod(total, 3600)
    m, s = divmod(remainder, 60)
    if h > 0:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m}:{s:02d}"
