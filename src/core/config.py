"""Configuration schema and loader."""
from dataclasses import dataclass, field
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
class NVDConfig:
    api_key: str = ""
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    rate_limit: int = 50  # requests per 30 seconds


@dataclass
class MSFConfig:
    host: str = "127.0.0.1"
    port: int = 55553
    password: str = ""
    module_types: List[str] = field(default_factory=lambda: ["exploit", "auxiliary"])
    batch_size: int = 200
    check_timeout: int = 30


@dataclass
class AuthCheckConfig:
    enabled: bool = True
    banner_timeout: int = 5
    msf_detect_timeout: int = 15
    max_auth_concurrency: int = 50


@dataclass
class Layer3Config:
    enabled: bool = True
    nvd: NVDConfig = field(default_factory=NVDConfig)
    msf: MSFConfig = field(default_factory=MSFConfig)
    target_concurrency: int = 200
    module_concurrency: int = 32
    auth: AuthCheckConfig = field(default_factory=AuthCheckConfig)


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
    layer3: Layer3Config
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
            layer3=Layer3Config(
                enabled=data.get("layer3", {}).get("enabled", True),
                nvd=NVDConfig(
                    api_key=data.get("layer3", {}).get("nvd", {}).get("api_key", ""),
                    base_url=data.get("layer3", {}).get("nvd", {}).get("base_url", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
                    rate_limit=data.get("layer3", {}).get("nvd", {}).get("rate_limit", 50),
                ),
                msf=MSFConfig(
                    host=data.get("layer3", {}).get("msf", {}).get("host", "127.0.0.1"),
                    port=data.get("layer3", {}).get("msf", {}).get("port", 55553),
                    password=data.get("layer3", {}).get("msf", {}).get("password", ""),
                    module_types=data.get("layer3", {}).get("msf", {}).get("module_types", ["exploit", "auxiliary"]),
                    batch_size=data.get("layer3", {}).get("msf", {}).get("batch_size", 200),
                    check_timeout=data.get("layer3", {}).get("msf", {}).get("check_timeout", 30),
                ),
                target_concurrency=data.get("layer3", {}).get("target_concurrency", 200),
                module_concurrency=data.get("layer3", {}).get("module_concurrency", 32),
                auth=AuthCheckConfig(
                    enabled=data.get("layer3", {}).get("auth", {}).get("enabled", True),
                    banner_timeout=data.get("layer3", {}).get("auth", {}).get("banner_timeout", 5),
                    msf_detect_timeout=data.get("layer3", {}).get("auth", {}).get("msf_detect_timeout", 15),
                    max_auth_concurrency=data.get("layer3", {}).get("auth", {}).get("max_auth_concurrency", 50),
                ),
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
        layer3=Layer3Config(),
        storage=StorageConfig(),
        queue=QueueConfig()
    )