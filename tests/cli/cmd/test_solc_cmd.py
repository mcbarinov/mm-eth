import json

from mm_std import run_command


def test_solc_cmd():
    cmd = "mm-eth solc tests/contracts/ERC20.sol -f json"
    res = run_command(cmd)
    assert res.code == 0
    assert json.loads(res.stdout)["bin"].startswith("60806040")
