from decimal import Decimal, localcontext
from typing import cast

import eth_utils
from web3.types import Wei


def to_wei(value: str | int | Decimal, decimals: int | None = None) -> Wei:
    if isinstance(value, int):
        return Wei(value)
    if isinstance(value, Decimal):
        if value != value.to_integral_value():
            raise ValueError(f"value must be integral number: {value}")
        return Wei(int(value))
    if isinstance(value, str):
        value = value.lower().replace(" ", "").strip()
        if value.endswith("gwei"):
            value = value.replace("gwei", "")
            return Wei(int(Decimal(value) * 1000000000))
        if value.endswith("ether"):
            value = value.replace("ether", "")
            return Wei(int(Decimal(value) * 1000000000000000000))
        if value.endswith("eth"):
            value = value.replace("eth", "")
            return Wei(int(Decimal(value) * 1000000000000000000))
        if value.endswith("t"):
            if decimals is None:
                raise ValueError("t without decimals")
            value = value.removesuffix("t")
            return Wei(int(Decimal(value) * 10**decimals))
        if value.isdigit():
            return Wei(int(value))
        raise ValueError("wrong value " + value)

    raise ValueError(f"value has a wrong type: {type(value)}")


def from_wei(value: int, unit: str, round_ndigits: int | None = None, decimals: int | None = None) -> Decimal:
    if value == 0:
        return Decimal(0)

    is_negative = value < 0
    if unit.lower() == "eth":
        unit = "ether"

    if unit.lower() == "t":
        if decimals is None:
            raise ValueError("t without decimals")
        with localcontext() as ctx:
            ctx.prec = 999
            res = Decimal(value=abs(value), context=ctx) / Decimal(10**decimals)
    else:
        res = cast(Decimal, eth_utils.from_wei(abs(value), unit))
    if round_ndigits is not None:
        res = round(res, ndigits=round_ndigits)
    return -1 * res if is_negative else res
