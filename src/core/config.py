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
    wait: int = 10
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
    signatures_dir: str = "config/signatures"
    prober_timeout: int = 10
    import_feed_batch: int = 100
    import_feed_interval: int = 5


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
            layers=Layer1Config(
                scanner_type=data.get("layers", {}).get("layer1", {}).get("scanner_type", "masscan"),
                batch_size=data.get("layers", {}).get("layer1", {}).get("batch_size", 10),
                backpressure=data.get("layers", {}).get("layer1", {}).get("backpressure", "block"),
                masscan_path=data.get("layers", {}).get("layer1", {}).get("masscan_path", "masscan"),
                scan_rate=data.get("layers", {}).get("layer1", {}).get("scan_rate", 10000),
                wait=data.get("layers", {}).get("layer1", {}).get("wait", 10),
                output_file=data.get("layers", {}).get("layer1", {}).get("output_file", "data/scans/results.txt"),
            ),
            layer2=Layer2Config(
                worker_pool=WorkerPoolConfig(**data.get("layers", {}).get("layer2", {}).get("worker_pool", {})),
                modules=data.get("layers", {}).get("layer2", {}).get("modules", []),
                router_strategy=data.get("layers", {}).get("layer2", {}).get("router_strategy", "optimistic"),
                signatures_dir=data.get("layers", {}).get("layer2", {}).get("signatures_dir", "config/signatures"),
                prober_timeout=data.get("layers", {}).get("layer2", {}).get("prober_timeout", 10),
                import_feed_batch=data.get("layers", {}).get("layer2", {}).get("import_feed_batch", 100),
                import_feed_interval=data.get("layers", {}).get("layer2", {}).get("import_feed_interval", 5),
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