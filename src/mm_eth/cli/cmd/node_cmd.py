from decimal import Decimal

import eth_utils
import mm_print
import pydash
from pydantic import BaseModel
from rich.live import Live
from rich.table import Table

from mm_eth import rpc, utils
from mm_eth.cli.cli import PrintFormat


class NodeInfo(BaseModel):
    url: str
    chain_id: int | str
    chain_name: str
    block_number: int | str
    base_fee: str | int | Decimal

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


async def run(urls: list[str], proxy: str | None, print_format: PrintFormat) -> None:
    urls = pydash.uniq(urls)
    result = []
    live_table = LiveTable(
        Table("url", "chain_id", "chain_name", "block_number", "base_fee", title="nodes"),
        ignore=print_format != PrintFormat.TABLE,
    )
    for url in urls:
        node_info = await _get_node_info(url, proxy)
        live_table.add_row(*node_info.table_row())
        result.append(node_info)

    live_table.stop()

    if print_format == PrintFormat.JSON:
        mm_print.json(data=result)
    # print_json(data=result)
    # table = Table(*["url", "chain_id", "chain_name", "block_number", "base_fee"], title="nodes")

    # with Live(table, refresh_per_second=0.5):
    #     for url in urls:
    #         table.add_row(url, str(chain_id), chain_name, str(block_number), base_fee)


async def _get_node_info(url: str, proxy: str | None) -> NodeInfo:
    chain_id_res = await rpc.eth_chain_id(url, proxy=proxy)
    chain_id = chain_id_res.value_or_error()
    chain_name = ""
    if chain_id_res.is_ok():
        chain_name = utils.name_network(chain_id_res.unwrap())
    block_number = (await rpc.eth_block_number(url, proxy=proxy)).value_or_error()
    base_fee = (
        (await rpc.get_base_fee_per_gas(url, proxy=proxy))
        .map(
            lambda ok: eth_utils.from_wei(ok, "gwei"),
        )
        .value_or_error()
    )
    return NodeInfo(url=url, chain_id=chain_id, chain_name=chain_name, block_number=block_number, base_fee=base_fee)
