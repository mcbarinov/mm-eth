import json

from mm_std import run_command


def test_node_cmd(anvil):
    cmd = f"mm-eth node {anvil.rpc_url} -f json"
    res = run_command(cmd)
    assert res.code == 0
    assert json.loads(res.stdout)[anvil.rpc_url]["chain_id"] == 31337
