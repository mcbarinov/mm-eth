from mm_std import run_command


def test_private_key_cmd(private_0, address_0):
    cmd = f"mm-eth wallet private-key {private_0}"
    res = run_command(cmd)
    assert res.code == 0
    assert res.stdout.strip().lower() == address_0.lower()
