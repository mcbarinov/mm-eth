from decimal import Decimal

import pytest

from mm_eth import utils


def test_to_wei():
    assert utils.to_wei(123) == 123
    assert utils.to_wei(Decimal("123")) == 123
    assert utils.to_wei("11navax") == 11000000000
    assert utils.to_wei("12.1t", decimals=6) == 12.1 * 10**6

    with pytest.raises(ValueError):
        utils.to_wei(Decimal("123.1"))
    with pytest.raises(ValueError):
        utils.to_wei("10t")


def test_to_token_wei():
    assert utils.to_token_wei("12.3t", 6) == 12300000
    assert utils.to_token_wei("12.3 t", 6) == 12300000


def test_from_wei():
    assert utils.from_wei(123000000000000000, "ether") == Decimal("0.123")
    assert utils.from_wei(0, "ether") == Decimal("0")
    assert utils.from_wei(12.1 * 10**6, "t", decimals=6) == Decimal("12.1")


def test_from_wei_str():
    assert utils.from_wei_str(123000000000000000, "ether", print_unit_name=False) == "0.123"
    assert utils.from_wei_str(123000000000000000, "ether") == "0.123eth"
    assert utils.from_wei_str(123000000000000000, "ether", round_ndigits=2) == "0.12eth"
    assert utils.from_wei_str(123000000000000000, "t", round_ndigits=2, decimals=18) == "0.12t"
    assert utils.from_wei_str(0, "ether", print_unit_name=False) == "0"
    assert utils.from_wei_str(12.1 * 10**6, "t", decimals=6, print_unit_name=False) == "12.1"


def test_to_checksum_address(address_0):
    assert utils.to_checksum_address(address_0.lower()) == address_0


def test_truncate_hex_str(address_0, private_0):
    assert utils.truncate_hex_str(address_0) == "0x10fd...6623"
    assert utils.truncate_hex_str(private_0, digits=3, replace_str="****") == "0x7bb****632"
