import json

from mm_eth.cli.cli import app


def test_node_cmd(anvil, cli_runner):
    res = cli_runner.invoke(app, f"node {anvil.rpc_url} -f json")
    assert res.exit_code == 0
    assert json.loads(res.stdout)[0]["chain_id"] == 31337
