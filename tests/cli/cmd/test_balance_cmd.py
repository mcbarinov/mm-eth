import json

from mm_std import run_command


def test_eth_balance_cmd(anvil, address_1):
    cmd = f"mm-eth balance {address_1} -u {anvil.rpc_url} -w -f json"
    res = run_command(cmd)
    assert res.code == 0
    assert json.loads(res.stdout)["eth_balance"] == "10000000000000000000000"
    assert json.loads(res.stdout)["nonce"] == 0
