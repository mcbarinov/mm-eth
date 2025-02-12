from pathlib import Path

from mm_std import pretty_print_toml


def run(command: str) -> None:
    command = command.replace("-", "_")
    example_file = Path(Path(__file__).parent.absolute(), "../examples", f"{command}.toml")
    pretty_print_toml(example_file.read_text())
