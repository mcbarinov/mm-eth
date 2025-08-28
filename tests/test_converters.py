from decimal import Decimal

import pytest

from mm_eth import converters


def test_to_wei():
    assert converters.to_wei(123) == 123
    assert converters.to_wei(Decimal(123)) == 123
    assert converters.to_wei("11gwei") == 11000000000
    assert converters.to_wei("12.1t", decimals=6) == 12.1 * 10**6

    with pytest.raises(ValueError):
        converters.to_wei(Decimal("123.1"))
    with pytest.raises(ValueError):
        converters.to_wei("10t")


def test_from_wei():
    assert converters.from_wei(123000000000000000, "ether") == Decimal("0.123")
    assert converters.from_wei(0, "ether") == Decimal(0)
    assert converters.from_wei(int(12.1 * 10**6), "t", decimals=6) == Decimal("12.1")
