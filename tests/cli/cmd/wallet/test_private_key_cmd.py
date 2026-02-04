"""Tests for the wallet private-key CLI command."""

from mm_eth.cli.cli import app


def test_private_key_cmd_ok(cli_runner, private_0, address_0):
    """Test private-key command returns correct address."""
    res = cli_runner.invoke(app, f"wallet private-key {private_0}")
    assert res.exit_code == 0
    assert res.stdout.strip().lower() == address_0.lower()


def test_private_key_cmd_err(cli_runner):
    """Test private-key command fails on invalid key."""
    res = cli_runner.invoke(app, "wallet private-key invalid_private_key")
    assert res.exit_code == 1
