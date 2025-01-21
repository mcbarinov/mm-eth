import json

from mm_std import run_command


def test_mnemonic_cmd(mnemonic, address_0, private_0):
    cmd = f"mm-eth wallet mnemonic -m '{mnemonic}'"
    res = run_command(cmd)
    assert res.code == 0
    assert json.loads(res.stdout)["accounts"][0] == {"address": address_0, "private": private_0}
