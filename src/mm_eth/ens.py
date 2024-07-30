from mm_std import Err, Ok, Result

from mm_eth.types import Nodes, Proxies
from mm_eth.utils import get_w3, random_node, random_proxy


def get_name(nodes: Nodes, address: str, timeout: int = 10, proxies: Proxies = None, attempts: int = 3) -> Result[str]:
    result = Err("not_started")
    for _ in range(attempts):
        try:
            w3 = get_w3(random_node(nodes), timeout=timeout, proxy=random_proxy(proxies))
            res = w3.ens.name(w3.to_checksum_address(address))  # type: ignore[union-attr]
            return Ok(res or "")
        except Exception as e:
            result = Err(e)
    return result
