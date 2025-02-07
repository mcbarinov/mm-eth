from pathlib import Path

from mm_std import print_plain


def run(command: str) -> None:
    command = command.replace("-", "_")
    example_file = Path(Path(__file__).parent.absolute(), "../examples", f"{command}.toml")
    print_plain(example_file.read_text())
