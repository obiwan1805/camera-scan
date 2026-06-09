"""Weight router — classify targets by weight + vendor."""
from src.storage.schemas import CameraFingerprint


class WeightRouter:
    """Classifies CameraFingerprint into strategy types.

    weight == 1.0 + vendor → "high" (NVD direct)
    weight < 1.0 + vendor  → "low"  (MSF check)
    vendor is None          → "skip" (no search possible)
    """

    def classify(self, item: CameraFingerprint) -> str:
        vendor = item.fingerprint.vendor if item.fingerprint else None
        if not vendor:
            return "skip"
        if item.weight == 1.0:
            return "high"
        return "low"
