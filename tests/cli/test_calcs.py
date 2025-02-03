import json

from mm_eth.cli import calcs


def test_calc_function_args():
    res = calcs.calc_function_args('["xxx", random(100,200), 100, "aaa", random(1,3)]')
    assert json.loads(res)[1] >= 100
