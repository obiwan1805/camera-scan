"""msfrpcd RPC client with module caching and batch check."""
import asyncio
from typing import Dict, List, Optional, Tuple
import msgpack
from src.core.config import MSFConfig
from src.layers.layer3_cve_searcher.cache import MSFModuleCache
from src.utils.logging import setup_logger


class MSFRPCClient:
    """Client for msfrpcd daemon — search modules, batch check, module cache."""

    def __init__(self, config: MSFConfig):
        self.config = config
        self._token: Optional[str] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._module_cache = MSFModuleCache()
        self._logger = setup_logger("MSFRPCClient")
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        """Connect to msfrpcd and authenticate."""
        try:
            self._reader, self._writer = await asyncio.open_connection(
                self.config.host, self.config.port
            )
            auth_msg = msgpack.packb({
                "method": "auth.login",
                "params": [self.config.password],
                "id": 0,
            })
            self._writer.write(auth_msg)
            await self._writer.drain()
            response = await self._reader.read(65536)
            result = msgpack.unpackb(response, raw=False)
            self._token = result.get("result", {}).get("token")
            if not self._token:
                raise ConnectionError("msfrpcd auth failed — check password")
            self._logger.info(f"Connected to msfrpcd at {self.config.host}:{self.config.port}")
        except Exception as e:
            self._logger.error(f"Failed to connect to msfrpcd: {e}")
            raise

    async def _call(self, method: str, params: list = None) -> dict:
        """Send RPC call and return response."""
        if not self._writer or self._writer.is_closing():
            raise ConnectionError("Not connected to msfrpcd")
        msg_id = id(method) % 10000
        msg = msgpack.packb({
            "method": method,
            "params": [self._token] + (params or []),
            "id": msg_id,
        })
        async with self._lock:
            self._writer.write(msg)
            await self._writer.drain()
            response = await asyncio.wait_for(
                self._reader.read(65536 * 4),
                timeout=self.config.check_timeout + 10,
            )
        return msgpack.unpackb(response, raw=False)

    def _extract_module_info(self, name: str, raw: dict) -> dict:
        """Extract structured info from MSF module metadata."""
        cves = []
        for ref in raw.get("references", []):
            if isinstance(ref, (list, tuple)) and len(ref) >= 2 and ref[0] == "CVE":
                cves.append(f"CVE-{ref[1]}")
        return {
            "name": name,
            "type": raw.get("type", ""),
            "description": raw.get("description", ""),
            "cves": cves,
        }

    async def search_modules(self, vendor: str, module_types: Optional[List[str]] = None) -> List[dict]:
        """Search MSF modules by vendor keyword. Results cached by vendor."""
        cached = self._module_cache.get(vendor)
        if cached is not None:
            self._logger.info(f"MSF module cache hit: {vendor}")
            return cached

        types = module_types or self.config.module_types
        all_modules = []

        for mtype in types:
            try:
                response = await self._call("db.modules.search", [vendor, {"module_type": mtype}])
                modules = response.get("result", {}).get("modules", [])
                for mod_name in modules:
                    try:
                        info_response = await self._call("module.info", [mtype, mod_name])
                        info = info_response.get("result", {})
                        extracted = self._extract_module_info(mod_name, info)
                        all_modules.append(extracted)
                    except Exception:
                        all_modules.append({"name": mod_name, "type": mtype, "cves": [], "description": ""})
            except Exception as e:
                self._logger.warning(f"MSF search failed for {vendor}/{mtype}: {e}")

        self._module_cache.put(vendor, all_modules)
        self._logger.info(f"MSF search: found {len(all_modules)} modules for '{vendor}'")
        return all_modules

    async def check(self, module_name: str, ip: str, port: int) -> dict:
        """Run MSF check on a single target."""
        parts = module_name.split("/")
        if len(parts) < 3:
            return {"ip": ip, "port": port, "status": "unknown", "cves": []}
        module_type = parts[0]

        try:
            await self._call("module.execute", [
                module_type,
                "/".join(parts[1:]),
                {"RHOSTS": ip, "RPORT": str(port)},
            ])
            return {"ip": ip, "port": port, "status": "unknown", "cves": []}
        except Exception as e:
            self._logger.error(f"MSF check failed for {module_name} on {ip}:{port}: {e}")
            return {"ip": ip, "port": port, "status": "error", "cves": []}

    def find_module_for_cve(self, vendor: str, cve_id: str) -> Optional[dict]:
        """Find MSF module that references a specific CVE (from cache)."""
        return self._module_cache.find_module_for_cve(vendor, cve_id)

    async def disconnect(self) -> None:
        if self._writer and not self._writer.is_closing():
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
        self._token = None
        self._reader = None
        self._writer = None
