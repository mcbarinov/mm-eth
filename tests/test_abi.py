from mm_eth import abi


def test_encode_function_signature():
    res = abi.encode_function_signature("transfer(address,uint256)")
    assert res == "0xa9059cbb"


def test_get_function_abi(erc20_abi):
    res = abi.get_function_abi(erc20_abi, "transfer")
    assert res["name"] == "transfer"


def test_encode_function_input_by_abi(erc20_abi):
    res = abi.encode_function_input_by_abi(erc20_abi, "transfer", ["0x2D88bd70Eb6c20302D4cdD69abeBEea02deEBEAE", 123456])
    input_data = "0xa9059cbb0000000000000000000000002d88bd70eb6c20302d4cdd69abebeea02deebeae000000000000000000000000000000000000000000000000000000000001e240"  # noqa: E501
    assert res == input_data


def test_encode_function_input_by_signature():
    res = abi.encode_function_input_by_signature(
        "transfer(address,uint256)",
        ["0x2D88bd70Eb6c20302D4cdD69abeBEea02deEBEAE", 123456],
    )
    input_data = "0xa9059cbb0000000000000000000000002d88bd70eb6c20302d4cdd69abebeea02deebeae000000000000000000000000000000000000000000000000000000000001e240"  # noqa: E501
    assert res == input_data
