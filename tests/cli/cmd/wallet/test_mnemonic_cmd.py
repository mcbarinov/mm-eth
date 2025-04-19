import json

from mm_eth.cli.cli import app


def test_mnemonic_cmd(cli_runner, mnemonic, address_0, private_0):
    res = cli_runner.invoke(app, f"wallet mnemonic -m '{mnemonic}'")
    assert res.exit_code == 0
    assert json.loads(res.stdout)["accounts"][0] == {"address": address_0, "private": private_0}
