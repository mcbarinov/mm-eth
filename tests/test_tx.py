from mm_eth import tx


def test_sign_legacy_tx(private_0, address_1):
    raw_tx = "0xf8601f0b169458487485c3858109f5a37e42546fe87473f79a4b218312399926a00739cb05ce6b1370b4dd53745e51202c2416427d47f60dd19cedbbec1ae8d5d0a064eea36637d9bd09b6e2efa8d20a906fd0146a6798a1b4db29457b6e9539862b"  # noqa: E501
    res = tx.sign_legacy_tx(
        nonce=31,
        gas_price=11,
        gas=22,
        private_key=private_0,
        chain_id=1,
        data="0x123999",
        value=33,
        to=address_1,
    )
    assert res.tx_hash == "0x0400cadbd22ce24ef98ffa0ffe337997758edbde5e4faebe6cda63d8246f545c"
    assert res.raw_tx == raw_tx


def test_decode_raw_tx(address_1):
    raw_tx = "0xf8601f0b169458487485c3858109f5a37e42546fe87473f79a4b218312399926a00739cb05ce6b1370b4dd53745e51202c2416427d47f60dd19cedbbec1ae8d5d0a064eea36637d9bd09b6e2efa8d20a906fd0146a6798a1b4db29457b6e9539862b"  # noqa: E501
    res = tx.decode_raw_tx(raw_tx)
    assert res.tx_hash == "0x0400cadbd22ce24ef98ffa0ffe337997758edbde5e4faebe6cda63d8246f545c"
    assert res.to == address_1


def test_encode_raw_tx_with_signature():
    raw_tx = "0xf8601f0b16949e8daea6fed7e024d9d4c802115a81e908905a8e218312399925a0bd1601a62708068a486c1b0fc793f368fbe629823cb9fd861c9c3c2a37aa7ca6a07dfc3abd01cbfa177fb77595b883ee1062d5146bc006b2c8afa6199defac1dc1"  # noqa: E501
    decoded_tx = tx.decode_raw_tx(raw_tx)
    res = tx.encode_raw_tx_with_signature(
        nonce=decoded_tx.nonce,
        gas_price=decoded_tx.gas_price,
        gas=decoded_tx.gas,
        v=decoded_tx.v,
        r=decoded_tx.r,
        s=decoded_tx.s,
        data=decoded_tx.data,
        value=decoded_tx.value,
        to=decoded_tx.to,
    )
    assert res == raw_tx
