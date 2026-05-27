"""Network utilities."""
import ipaddress
import socket


async def get_banner(ip: str, port: int, timeout: float = 2.0) -> bytes:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        banner = await reader.read(256)
        writer.close()
        await writer.wait_closed()
        return banner
    except Exception:
        return b""


def is_private_ip(ip: str) -> bool:
    try:
        parts = list(map(int, ip.split(".")))
        return (
            (parts[0] == 10) or
            (parts[0] == 172 and 16 <= parts[1] <= 31) or
            (parts[0] == 192 and parts[1] == 168)
        )
    except ValueError:
        return False

def count_ips_in_cidr(cidr: str) -> int:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return network.num_addresses
    except ValueError:
        return 0

def count_total_ips(cidr_list: list) -> int:
    return sum(count_ips_in_cidr(cidr) for cidr in cidr_list)

def count_ips_in_range(spec: str) -> int:
    """Count IPs in CIDR or IP range (e.g. '1.52.0.0-1.52.246.255')."""
    if "/" in spec:
        return count_ips_in_cidr(spec)
    if "-" in spec:
        parts = spec.split("-")
        if len(parts) == 2:
            try:
                start = int(ipaddress.ip_address(parts[0].strip()))
                end = int(ipaddress.ip_address(parts[1].strip()))
                return max(0, end - start + 1)
            except ValueError:
                return 0
    return count_ips_in_cidr(spec)