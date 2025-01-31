from hexbytes import HexBytes
from mm_std import CustomJSONEncoder


class EthJsonEncoder(CustomJSONEncoder):
    def default(self, o: object) -> object:
        if isinstance(o, HexBytes):
            return o.hex()
        return super().default(o)


def json_default(o: object) -> str:
    if isinstance(o, HexBytes):
        return o.to_0x_hex()
    raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")
