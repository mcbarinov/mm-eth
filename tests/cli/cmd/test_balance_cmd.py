import json

from mm_eth.cli.cli import app


def test_eth_balance_cmd(anvil, cli_runner, address_1):
    res = cli_runner.invoke(app, f"balance {address_1} -u {anvil.rpc_url} -w -f json")
    assert res.exit_code == 0
    assert json.loads(res.stdout)["eth_balance"] == 10000000000000000000000
    assert json.loads(res.stdout)["nonce"] == 0
