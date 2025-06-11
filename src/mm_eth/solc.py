import random
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import mm_std
from mm_result import Result


@dataclass
class SolcResult:
    bin: str
    abi: str


def solc(contract_name: str, contract_path: Path, tmp_dir: Path) -> Result[SolcResult]:
    # Sanitize contract name to avoid unsafe characters in directory name
    safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", contract_name)

    # Expand ~ in paths if present
    contract_path = contract_path.expanduser().resolve()
    tmp_dir = tmp_dir.expanduser().resolve()

    work_dir = tmp_dir / f"solc_{safe_name}_{random.randint(0, 100_000_000)}"
    abi_path = work_dir / f"{contract_name}.abi"
    bin_path = work_dir / f"{contract_name}.bin"

    work_dir_created = False
    try:
        work_dir.mkdir(parents=True, exist_ok=False)
        work_dir_created = True

        cmd = f"solc -o '{work_dir}' --abi --bin --optimize '{contract_path}'"
        result = mm_std.shell(cmd)
        if result.code != 0:
            return Result.err(f"solc error: {result.stderr}")

        abi = abi_path.read_text()
        bin_ = bin_path.read_text()

        return Result.ok(SolcResult(bin=bin_, abi=abi))
    except Exception as e:
        return Result.err(e)
    finally:
        if work_dir_created:
            shutil.rmtree(work_dir, ignore_errors=True)
