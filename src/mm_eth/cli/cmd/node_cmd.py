from mm_std import Ok, PrintFormat, print_json, print_plain
from rich.live import Live
from rich.table import Table

from mm_eth import rpc
from mm_eth.utils import from_wei_str, name_network


def run(urls: list[str], print_format: PrintFormat, proxy: str | None) -> None:
    json_result: dict[str, object] = {}
    table = Table(title="nodes")
    if print_format == PrintFormat.TABLE:
        table.add_column("url")
        table.add_column("chain_id")
        table.add_column("chain_name")
        table.add_column("block_number")
        table.add_column("base_fee")

    with Live(table, refresh_per_second=0.5):
        for url in urls:
            chain_id_res = rpc.eth_chain_id(url, timeout=10, proxies=proxy)
            chain_id = chain_id_res.ok_or_err()
            chain_name = ""
            if isinstance(chain_id_res, Ok):
                chain_name = name_network(chain_id_res.ok)
            block_number = rpc.eth_block_number(url, timeout=10, proxies=proxy).ok_or_err()
            base_fee = rpc.get_base_fee_per_gas(url, timeout=10, proxies=proxy).map_or_else(
                lambda err: err,
                lambda ok: from_wei_str(ok, "gwei"),
            )

            json_result[url] = {
                "chain_id": chain_id,
                "chain_name": chain_name,
                "block_number": block_number,
                "base_fee": base_fee,
            }
            if print_format == PrintFormat.TABLE:
                table.add_row(url, str(chain_id), chain_name, str(block_number), base_fee)
            print_plain(f"url: {url}", print_format)
            print_plain(f"chain_id: {chain_id}", print_format)
            print_plain(f"chain_name: {chain_name}", print_format)
            print_plain(f"block_number: {block_number}", print_format)
            print_plain(f"base_fee: {base_fee}", print_format)
            print_plain("", print_format)

    print_json(json_result, print_format)
