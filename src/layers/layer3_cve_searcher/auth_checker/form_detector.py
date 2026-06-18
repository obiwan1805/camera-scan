"""HTML/JS login form analysis for web authentication detection."""
import re
from html.parser import HTMLParser
from typing import Optional, List, Tuple, Dict
import aiohttp
from src.core.config import AuthCheckConfig
from src.storage.schemas import AuthInfo
from src.utils.logging import setup_logger

MAX_RAW_RESPONSE = 512

LOGIN_PATHS = [
    "/", "/login", "/login.html", "/login.asp", "/login.cgi",
    "/admin", "/admin/login",
    "/cgi-bin/login", "/cgi-bin/login.cgi",
    "/webui/", "/webui/login",
    "/doc/page/login.asp",
]

PASSWORD_NAME_PATTERN = re.compile(r"^(pass|pwd|password)", re.IGNORECASE)
USERNAME_NAME_PATTERN = re.compile(
    r"^(user|username|login|email|account|name)$", re.IGNORECASE
)
CSRF_NAME_PATTERN = re.compile(r"(csrf|token|_verify|nonce)", re.IGNORECASE)

META_REFRESH = re.compile(
    r'<meta[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*'
    r'content\s*=\s*["\'][^"\']*url\s*=\s*([^"\'\s>]+)',
    re.IGNORECASE,
)
JS_LOCATION = re.compile(
    r'(?:window\.location|location\.href|location\.replace)\s*'
    r'[=(]\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
LINK_HREF = re.compile(
    r'<a[^>]*href\s*=\s*["\']([^"\']*(?:login|auth|signin|sign_in)[^"\']*)["\']',
    re.IGNORECASE,
)

JS_PASSWORD_INDICATORS = [
    re.compile(r'getElementById\s*\(\s*["\']password["\']', re.IGNORECASE),
    re.compile(r"querySelector\s*\(\s*['\"].*type.*password", re.IGNORECASE),
    re.compile(r'\.type\s*=\s*["\']password["\']', re.IGNORECASE),
]
JS_AUTH_ENDPOINTS = re.compile(
    r'(?:fetch|XMLHttpRequest|\.ajax|\.post|\.get)\s*\('
    r'\s*["\'][^"\']*(?:/api/login|/api/auth|/auth|/login|/signin)["\']',
    re.IGNORECASE,
)


class _FormParser(HTMLParser):
    """Parse HTML to extract forms with password-related inputs."""

    def __init__(self):
        super().__init__()
        self._in_form = False
        self._forms: List[Dict] = []
        self._current_form: Optional[Dict] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        tag_lower = tag.lower()

        if tag_lower == "form":
            self._in_form = True
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "GET").upper(),
                "inputs": [],
            }

        elif tag_lower == "input" and self._in_form and self._current_form is not None:
            self._current_form["inputs"].append(attr_dict)

        elif tag_lower == "input" and not self._in_form:
            if self._current_form is None:
                self._current_form = {"action": "", "method": "GET", "inputs": []}
            self._current_form["inputs"].append(attr_dict)

    def handle_endtag(self, tag: str):
        if tag.lower() == "form" and self._in_form:
            self._in_form = False
            if self._current_form is not None:
                self._forms.append(self._current_form)
                self._current_form = None

    def get_login_forms(self) -> List[Dict]:
        all_forms = list(self._forms)
        if self._current_form and self._current_form.get("inputs"):
            all_forms.append(self._current_form)

        results = []
        for form in all_forms:
            has_password = False
            for inp in form["inputs"]:
                input_type = inp.get("type", "").lower()
                input_name = inp.get("name", "").lower()
                if input_type == "password":
                    has_password = True
                    break
                if PASSWORD_NAME_PATTERN.match(input_name) and input_type != "hidden":
                    has_password = True
                    break
                placeholder = inp.get("placeholder", "").lower()
                if "password" in placeholder:
                    has_password = True
                    break
            if has_password:
                results.append(form)
        return results


class FormDetector:
    def __init__(self, config: AuthCheckConfig):
        self._config = config
        self._logger = setup_logger("FormDetector")

    async def detect(self, ip: str, port: int, protocol: str) -> AuthInfo:
        scheme = "https" if protocol == "https" else "http"
        default = AuthInfo(
            port=port, protocol=protocol, has_login=False, auth_type="unknown",
        )

        try:
            timeout = aiohttp.ClientTimeout(total=self._config.banner_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                paths = list(LOGIN_PATHS)
                discovered = await self._discover_paths(session, ip, port, scheme)
                for p in discovered:
                    if p not in paths:
                        paths.append(p)

                best_result: Optional[AuthInfo] = None
                js_result: Optional[AuthInfo] = None

                for path in paths:
                    url = f"{scheme}://{ip}:{port}{path}"
                    try:
                        async with session.get(url, ssl=False, allow_redirects=True) as resp:
                            if resp.status == 401:
                                auth_header = resp.headers.get("WWW-Authenticate", "")
                                auth_type = self._parse_auth_type(auth_header)
                                return AuthInfo(
                                    port=port, protocol=protocol, has_login=True,
                                    auth_type=auth_type,
                                    raw_response=f"HTTP 401 at {path}"[:MAX_RAW_RESPONSE],
                                    login_url=url,
                                )

                            html = await resp.text(errors="replace")
                            cookies = {k: v.value for k, v in resp.cookies.items()}

                            form_result = self._analyze_form(html, url, port, protocol, cookies)
                            if form_result and (best_result is None or form_result.form_action):
                                best_result = form_result

                            if js_result is None:
                                js_res = self._analyze_js(html, url, port, protocol)
                                if js_res:
                                    js_result = js_res

                    except Exception:
                        continue

                if best_result:
                    return best_result
                if js_result:
                    return js_result

        except Exception as e:
            self._logger.debug(f"Form detection failed for {ip}:{port}: {e}")

        return default

    async def _discover_paths(
        self, session: aiohttp.ClientSession, ip: str, port: int, scheme: str,
    ) -> List[str]:
        paths: List[str] = []
        url = f"{scheme}://{ip}:{port}/"
        try:
            async with session.get(url, ssl=False, allow_redirects=True) as resp:
                html = await resp.text(errors="replace")

                match = META_REFRESH.search(html)
                if match:
                    path = self._normalize_path(match.group(1))
                    if path:
                        paths.append(path)

                for match in JS_LOCATION.finditer(html):
                    path = self._normalize_path(match.group(1))
                    if path:
                        paths.append(path)

                for match in LINK_HREF.finditer(html):
                    path = self._normalize_path(match.group(1))
                    if path:
                        paths.append(path)

        except Exception:
            pass
        return paths

    def _normalize_path(self, raw: str) -> Optional[str]:
        raw = raw.strip()
        if raw.startswith("http://") or raw.startswith("https://"):
            from urllib.parse import urlparse
            raw = urlparse(raw).path
        if not raw or not raw.startswith("/"):
            raw = "/" + raw
        return raw if raw != "/" else None

    def _parse_auth_type(self, header: str) -> str:
        h = header.lower()
        if "basic" in h:
            return "basic"
        if "digest" in h:
            return "digest"
        return "unknown"

    def _analyze_form(
        self, html: str, url: str, port: int, protocol: str, cookies: dict,
    ) -> Optional[AuthInfo]:
        parser = _FormParser()
        try:
            parser.feed(html)
        except Exception:
            return None

        forms = parser.get_login_forms()
        if not forms:
            return None

        form = forms[0]
        username_field = None
        password_field = None
        hidden_fields = {}
        csrf_token_field = None
        csrf_token_value = None

        for inp in form["inputs"]:
            input_type = inp.get("type", "").lower()
            input_name = inp.get("name", "")

            if input_type == "hidden":
                hidden_fields[input_name] = inp.get("value", "")
                if CSRF_NAME_PATTERN.search(input_name):
                    csrf_token_field = input_name
                    csrf_token_value = inp.get("value", "")
                continue

            if input_type == "password" or (
                PASSWORD_NAME_PATTERN.match(input_name) and input_type != "hidden"
            ):
                password_field = input_name
                continue

            placeholder = inp.get("placeholder", "").lower()
            if "password" in placeholder:
                password_field = input_name
                continue

            if input_type in ("text", "email", "") or USERNAME_NAME_PATTERN.match(input_name):
                if username_field is None:
                    username_field = input_name

        return AuthInfo(
            port=port,
            protocol=protocol,
            has_login=True,
            auth_type="form",
            raw_response=f"Login form at {url}"[:MAX_RAW_RESPONSE],
            form_action=form["action"] or None,
            form_method=form["method"],
            username_field=username_field,
            password_field=password_field,
            hidden_fields=hidden_fields or None,
            csrf_token_field=csrf_token_field,
            csrf_token_value=csrf_token_value,
            login_url=url,
            cookies=cookies or None,
        )

    def _analyze_js(
        self, html: str, url: str, port: int, protocol: str,
    ) -> Optional[AuthInfo]:
        script_blocks = re.findall(
            r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE
        )
        if not script_blocks:
            return None

        js_text = "\n".join(script_blocks)

        for pattern in JS_PASSWORD_INDICATORS:
            if pattern.search(js_text):
                return AuthInfo(
                    port=port,
                    protocol=protocol,
                    has_login=True,
                    auth_type="js_rendered",
                    raw_response=f"JS login indicators at {url}"[:MAX_RAW_RESPONSE],
                    login_url=url,
                )

        if JS_AUTH_ENDPOINTS.search(js_text):
            return AuthInfo(
                port=port,
                protocol=protocol,
                has_login=True,
                auth_type="js_rendered",
                raw_response=f"JS auth endpoint at {url}"[:MAX_RAW_RESPONSE],
                login_url=url,
            )

        return None
