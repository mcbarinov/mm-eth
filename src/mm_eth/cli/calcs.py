import mm_cryptocurrency

from mm_eth.cli.validators import SUFFIX_DECIMALS


def calc_eth_expression(expression: str, variables: dict[str, int] | None = None) -> int:
    return mm_cryptocurrency.calc_expression_with_vars(expression, variables, unit_decimals=SUFFIX_DECIMALS)


def calc_token_expression(expression: str, token_decimals: int, variables: dict[str, int] | None = None) -> int:
    return mm_cryptocurrency.calc_expression_with_vars(expression, variables, unit_decimals={"t": token_decimals})
