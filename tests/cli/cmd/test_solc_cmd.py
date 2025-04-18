import json
from pathlib import Path

from mm_eth.cli.cli import app


def test_solc_cmd(cli_runner):
    current_dir = Path(__file__).resolve().parent
    contract_path = current_dir / "../../contracts/ERC20.sol"
    res = cli_runner.invoke(app, f"solc {contract_path} -f json")
    assert res.exit_code == 0
    assert json.loads(res.stdout)["bin"].startswith("6080604052348015610")
