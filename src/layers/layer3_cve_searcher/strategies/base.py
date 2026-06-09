"""Abstract base for CVE search strategies."""
from abc import ABC, abstractmethod
from typing import Optional
from src.storage.schemas import CameraFingerprint


class SearchStrategy(ABC):
    @abstractmethod
    async def execute(
        self,
        item: CameraFingerprint,
        nvd_client,
        msf_client,
        storage,
    ) -> Optional[CameraFingerprint]:
        """Process a CameraFingerprint and return enriched version."""
        pass
