from __future__ import annotations

import time
from subprocess import Popen  # nosec

from mm_std import Err, Ok, Result
from mm_std.net import get_free_local_port

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

    def check(self) -> bool:
        res = rpc.eth_chain_id(self.rpc_url)
        return isinstance(res, Ok) and res.ok == self.chain_id

    @property
    def rpc_url(self) -> str:
        return f"http://localhost:{self.port}"

    @classmethod
    def launch(
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
            if anvil.check():
                return Ok(anvil)
            port = get_free_local_port()

        return Err("can't lauch anvil")
