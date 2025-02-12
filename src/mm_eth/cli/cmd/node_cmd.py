import pydash
from mm_std import Ok, PrintFormat, print_json
from pydantic import BaseModel
from rich.live import Live
from rich.table import Table

from mm_eth import rpc
from mm_eth.utils import from_wei_str, name_network


class NodeInfo(BaseModel):
    url: str
    chain_id: int | str
    chain_name: str
    block_number: int | str
    base_fee: str

    def table_row(self) -> list[object]:
        return [self.url, self.chain_id, self.chain_name, self.block_number, self.base_fee]


class LiveTable:
    def __init__(self, table: Table, ignore: bool = False) -> None:
        self.ignore = ignore
        if ignore:
            return
        self.table = table
        self.live = Live(table, auto_refresh=False)
        self.live.start()

    def add_row(self, *args: object) -> None:
        if self.ignore:
            return
        self.table.add_row(*(str(a) for a in args))
        self.live.refresh()

    def stop(self) -> None:
        if self.ignore:
            return
        self.live.stop()


def run(urls: list[str], proxy: str | None, print_format: PrintFormat) -> None:
    urls = pydash.uniq(urls)
    result = []
    live_table = LiveTable(
        Table("url", "chain_id", "chain_name", "block_number", "base_fee", title="nodes"),
        ignore=print_format != PrintFormat.TABLE,
    )
    for url in urls:
        node_info = _get_node_info(url, proxy)
        live_table.add_row(*node_info.table_row())
        result.append(node_info)

    live_table.stop()

    if print_format == PrintFormat.JSON:
        print_json(data=result)
    # print_json(data=result)
    # table = Table(*["url", "chain_id", "chain_name", "block_number", "base_fee"], title="nodes")

    # with Live(table, refresh_per_second=0.5):
    #     for url in urls:
    #         table.add_row(url, str(chain_id), chain_name, str(block_number), base_fee)


def _get_node_info(url: str, proxy: str | None) -> NodeInfo:
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
    return NodeInfo(url=url, chain_id=chain_id, chain_name=chain_name, block_number=block_number, base_fee=base_fee)
