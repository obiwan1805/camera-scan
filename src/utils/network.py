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