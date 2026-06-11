"""msfrpcd RPC client — HTTP msgpack API with module caching and batch check."""
import asyncio
from typing import Dict, List, Optional
import msgpack
import aiohttp
from src.core.config import MSFConfig
from src.layers.layer3_cve_searcher.cache import MSFModuleCache
from src.utils.logging import setup_logger


class MSFRPCClient:
    """Client for msfrpcd daemon via HTTP + msgpack.

    msfrpcd exposes an HTTP API at /api that accepts msgpack-encoded requests.
    Format: msgpack.packb([method, param1, param2, ...])
    Auth: ['auth.login', username, password] → {'result': 'success', 'token': '...'}
    All subsequent calls include token as first param after method.
    """

    def __init__(self, config: MSFConfig):
        self.config = config
        self._token: Optional[str] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._base_url = f"http://{config.host}:{config.port}/api"
        self._module_cache = MSFModuleCache()
        self._logger = setup_logger("MSFRPCClient")
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        """Connect to msfrpcd and authenticate via HTTP msgpack."""
        try:
            self._session = aiohttp.ClientSession()
            result = await self._call("auth.login", "msf", self.config.password)
            # Response: {'result': 'success', 'token': 'TEMP...'}
            self._token = self._val(result, "token")
            if isinstance(self._token, bytes):
                self._token = self._token.decode()
            if not self._token:
                raise ConnectionError("msfrpcd auth failed — check password")
            self._logger.info(f"Connected to msfrpcd at {self.config.host}:{self.config.port}")
        except Exception as e:
            self._logger.error(f"Failed to connect to msfrpcd: {e}")
            if self._session and not self._session.closed:
                await self._session.close()
                self._session = None
            raise

    async def _call(self, method: str, *params) -> dict:
        """Send msgpack RPC call via HTTP POST.

        Returns the full response dict. msfrpcd returns different key names
        depending on the method: 'result', 'token', 'modules', etc.
        """
        if not self._session or self._session.closed:
            raise ConnectionError("Not connected to msfrpcd")

        # Build msgpack payload: [method, param1, param2, ...]
        # For authenticated calls, inject token as first param after method
        if self._token and method != "auth.login":
            payload = msgpack.packb([method, self._token] + list(params))
        else:
            payload = msgpack.packb([method] + list(params))

        async with self._lock:
            async with self._session.post(
                self._base_url,
                data=payload,
                headers={"Content-Type": "binary/message-pack"},
                timeout=aiohttp.ClientTimeout(total=self.config.check_timeout + 10),
            ) as resp:
                data = await resp.read()

        result = msgpack.unpackb(data, raw=False, strict_map_key=False)
        if result.get("error") or result.get(b"error"):
            error_msg = result.get("error_string", result.get(b"error_string", "Unknown error"))
            if isinstance(error_msg, bytes):
                error_msg = error_msg.decode()
            raise RuntimeError(f"msfrpcd error: {error_msg}")

        return result

    @staticmethod
    def _val(response: dict, key: str):
        """Get value from response dict, handling both str and bytes keys."""
        return response.get(key, response.get(key.encode()))

    def _extract_module_info(self, name: str, raw: dict) -> dict:
        """Extract structured info from MSF module metadata."""
        cves = []
        refs = raw.get("references", raw.get(b"references", []))
        for ref in refs:
            if isinstance(ref, (list, tuple)) and len(ref) >= 2:
                ref_type = ref[0]
                ref_val = ref[1]
                if isinstance(ref_type, bytes):
                    ref_type = ref_type.decode()
                if isinstance(ref_val, bytes):
                    ref_val = ref_val.decode()
                if ref_type == "CVE":
                    cves.append(f"CVE-{ref_val}")
        desc = raw.get("description", raw.get(b"description", ""))
        if isinstance(desc, bytes):
            desc = desc.decode()
        mtype = raw.get("type", raw.get(b"type", ""))
        if isinstance(mtype, bytes):
            mtype = mtype.decode()
        return {
            "name": name,
            "type": mtype,
            "description": desc,
            "cves": cves,
        }

    async def search_modules(self, vendor: str, module_types: Optional[List[str]] = None) -> List[dict]:
        """Search MSF modules by vendor keyword. Results cached by vendor.

        Uses module.<type> (e.g., module.exploits) to list all modules,
        filters by vendor keyword, then fetches info for matching modules.
        """
        cached = self._module_cache.get(vendor)
        if cached is not None:
            self._logger.info(f"MSF module cache hit: {vendor}")
            return cached

        types = module_types or self.config.module_types
        all_modules = []
        vendor_lower = vendor.lower()

        for mtype in types:
            # msfrpcd API: module.exploits, module.auxiliary, module.payloads, etc.
            method_map = {"exploit": "module.exploits", "auxiliary": "module.auxiliary",
                          "payload": "module.payloads", "encoder": "module.encoders",
                          "nop": "module.nops", "post": "module.post"}
            api_method = method_map.get(mtype, f"module.{mtype}")
            try:
                # module.exploits / module.auxiliary → {'modules': ['name1', ...]}
                response = await self._call(api_method)
                modules_list = self._val(response, "modules") or []

                # Filter by vendor keyword
                matching = []
                for mod_name in modules_list:
                    if isinstance(mod_name, bytes):
                        mod_name = mod_name.decode()
                    if vendor_lower in mod_name.lower():
                        matching.append(mod_name)

                # Fetch info for each matching module
                for mod_name in matching:
                    try:
                        # module.info(token, mtype, module_path)
                        # module_path is everything after the type prefix
                        mod_path = mod_name
                        if mod_name.startswith(f"{mtype}/"):
                            mod_path = mod_name[len(mtype) + 1:]

                        info_response = await self._call("module.info", mtype, mod_path)
                        # module.info returns fields at top level (name, references, etc.)
                        # If there's a 'result' key, use that; otherwise use the whole response
                        info = self._val(info_response, "result")
                        if not info or not isinstance(info, dict):
                            info = info_response

                        extracted = self._extract_module_info(mod_name, info)
                        all_modules.append(extracted)
                    except Exception as e:
                        self._logger.debug(f"module.info failed for {mod_name}: {e}")
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
        module_path = "/".join(parts[1:])

        try:
            response = await self._call(
                "module.execute",
                module_type,
                module_path,
                {"RHOSTS": ip, "RPORT": str(port)},
            )
            job_id = self._val(response, "result")
            return {"ip": ip, "port": port, "status": "launched", "job_id": job_id, "cves": []}
        except Exception as e:
            self._logger.error(f"MSF check failed for {module_name} on {ip}:{port}: {e}")
            return {"ip": ip, "port": port, "status": "error", "cves": []}

    def find_module_for_cve(self, vendor: str, cve_id: str) -> Optional[dict]:
        """Find MSF module that references a specific CVE (from cache)."""
        return self._module_cache.find_module_for_cve(vendor, cve_id)

    async def disconnect(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
        self._token = None
