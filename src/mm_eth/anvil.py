from __future__ import annotations

import socket
import time
from subprocess import Popen  # nosec
from typing import cast

from mm_result import Result

from mm_eth import account, rpc


class Anvil:
    def __init__(self, *, chain_id: int, port: int, mnemonic: str) -> None:
        self.chain_id = chain_id
        self.port = port
        self.mnemonic = mnemonic
        self.process: Popen | None = None  # type: ignore[type-arg]

    def start_process(self) -> None:
        cmd = f"anvil -m '{self.mnemonic}' -p {self.port} --chain-id {self.chain_id}"
        self.process = Popen(cmd, shell=True)  # noqa: S602 # nosec
        time.sleep(3)

    def stop(self) -> None:
        if self.process:
            self.process.kill()

    async def check(self) -> bool:
        res = await rpc.eth_chain_id(self.rpc_url)
        return res.is_ok() and res.unwrap() == self.chain_id

    @property
    def rpc_url(self) -> str:
        return f"http://localhost:{self.port}"

    @classmethod
    async def launch(
        cls,
        chain_id: int = 31337,
        port: int | None = None,
        mnemonic: str = "",
        attempts: int = 3,
    ) -> Result[Anvil]:
        if not mnemonic:
            mnemonic = account.generate_mnemonic()

        for _ in range(attempts):
            if not port:
                port = get_free_local_port()
            anvil = Anvil(chain_id=chain_id, port=port, mnemonic=mnemonic)
            anvil.start_process()
            if await anvil.check():
                return Result.ok(anvil)
            port = get_free_local_port()

        return Result.err("can't launch anvil")


def get_free_local_port() -> int:
    sock = socket.socket()
    sock.bind(("", 0))
    port = sock.getsockname()[1]
    sock.close()
    return cast(int, port)
