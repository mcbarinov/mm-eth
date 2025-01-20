import random
import shutil
from dataclasses import dataclass
from pathlib import Path

from mm_std import Err, Ok, Result, run_command


@dataclass
class SolcResult:
    bin: str
    abi: str


def solc(contract_name: str, contract_path: str, tmp_dir: str) -> Result[SolcResult]:
    if tmp_dir.startswith("~"):
        tmp_dir = Path(tmp_dir).expanduser().as_posix()
    if contract_path.startswith("~"):
        contract_path = Path(contract_path).expanduser().as_posix()
    work_dir = f"{tmp_dir}/solc_{contract_name}_{random.randint(0, 100_000_000)}"
    abi_path = f"{work_dir}/{contract_name}.abi"
    bin_path = f"{work_dir}/{contract_name}.bin"
    try:
        Path(work_dir).mkdir(parents=True)
        cmd = f"solc -o '{work_dir}' --abi --bin --optimize {contract_path}"
        run_command(cmd)
        abi = Path(abi_path).read_text()
        bin_ = Path(bin_path).read_text()
        return Ok(SolcResult(bin=bin_, abi=abi))
    except Exception as e:
        return Err(f"exception: {e}")
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
