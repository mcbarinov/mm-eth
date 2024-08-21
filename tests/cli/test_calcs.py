import json

import pytest

from mm_eth.cli import calcs
from mm_eth.utils import to_wei


def test_calc_var_wei_value():
    assert calcs.calc_var_wei_value("100") == 100
    assert calcs.calc_var_wei_value("10 + 2 - 5") == 7
    assert calcs.calc_var_wei_value("10 - random(2,2)") == 8
    assert calcs.calc_var_wei_value("10gwei - random(2gwei,2gwei)") == to_wei("8gwei")
    assert calcs.calc_var_wei_value("1.5base + 1", var_value=10, var_name="base") == 16
    assert calcs.calc_var_wei_value("1.5estimate + 1", var_value=10, var_name="estimate") == 16
    assert calcs.calc_var_wei_value("12.2 gwei") == to_wei("12.2gwei")
    assert calcs.calc_var_wei_value("12.2 eth") == to_wei("12.2eth")
    assert calcs.calc_var_wei_value("12.2 ether") == to_wei("12.2eth")
    assert calcs.calc_var_wei_value("12.2 t", decimals=6) == 12.2 * 10**6

    with pytest.raises(ValueError):
        calcs.calc_var_wei_value("fff")
    with pytest.raises(ValueError):
        calcs.calc_var_wei_value("12.3 gwei + base", var_name="base")
    with pytest.raises(ValueError):
        calcs.calc_var_wei_value("1.5estimate + 1", var_value=10)
    with pytest.raises(ValueError):
        calcs.calc_var_wei_value("1.1t")


def test_calc_function_args():
    res = calcs.calc_function_args('["xxx", random(100,200), 100, "aaa", random(1,3)]')
    assert json.loads(res)[1] >= 100
