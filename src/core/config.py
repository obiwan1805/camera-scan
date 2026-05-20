"""Configuration schema and loader."""
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import yaml


@dataclass
class Layer1Config:
    scanner_type: str = "masscan"
    batch_size: int = 10
    backpressure: str = "block"
    masscan_path: str = "masscan"
    scan_rate: int = 10000
    output_file: str = "data/scans/results.txt"


@dataclass
class WorkerPoolConfig:
    pool_type: str = "semaphore"
    max_concurrent: int = 200


@dataclass
class Layer2Config:
    worker_pool: WorkerPoolConfig
    modules: List[str]
    router_strategy: str = "optimistic"


@dataclass
class StorageConfig:
    backend: str = "sqlite"
    path: str = "data/camera_scan.db"


@dataclass
class QueueConfig:
    maxsize: int = 1000
    type: str = "multiprocessing"


@dataclass
class Config:
    layers: Layer1Config
    layer2: Layer2Config
    storage: StorageConfig
    queue: QueueConfig

    @classmethod
    def from_yaml(cls, path: str) -> "Config":
        with open(path) as f:
            data = yaml.safe_load(f)

        return cls(
            layers=Layer1Config(**data.get("layers", {}).get("layer1", {})),
            layer2=Layer2Config(
                worker_pool=WorkerPoolConfig(**data.get("layers", {}).get("layer2", {}).get("worker_pool", {})),
                modules=data.get("layers", {}).get("layer2", {}).get("modules", []),
                router_strategy=data.get("layers", {}).get("layer2", {}).get("router_strategy", "optimistic")
            ),
            storage=StorageConfig(**data.get("storage", {})),
            queue=QueueConfig(**data.get("queue", {}))
        )


def get_default_config() -> Config:
    config_path = Path(__file__).parent.parent.parent / "config" / "default.yaml"
    if config_path.exists():
        return Config.from_yaml(str(config_path))
    return Config(
        layers=Layer1Config(),
        layer2=Layer2Config(worker_pool=WorkerPoolConfig(), modules=["http", "rtsp", "onvif"]),
        storage=StorageConfig(),
        queue=QueueConfig()
    )