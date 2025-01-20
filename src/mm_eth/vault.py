from mm_std import Err, Ok, Result, hr

from mm_eth.account import private_to_address


def read_keys_from_vault(keys_url: str, token: str) -> Result[dict[str, str]]:
    data = None
    try:
        # keys_url example, https://vault.site.com:8200/v1/kv/keys1
        res = hr(keys_url, headers={"X-Vault-Token": token})
        data = res.json
        return Ok(res.json["data"], data=data)
    except Exception as e:
        return Err(f"exception: {e}", data=data)


def set_keys_from_vault(keys_url: str, token: str, private_keys: list[str], verify_tls: bool = True) -> Result[bool]:
    """It works with KV version=1 only!!!"""
    # TODO: check that keys_url is kv1 version and error if it's kv2
    data = None
    try:
        # keys_url example, https://vault.site.com:8200/v1/kv/keys1
        keys: dict[str, str] = {}
        for private_key in private_keys:
            address = private_to_address(private_key)
            if address is None:
                return Err("wrong private key", data=data)
            keys[address] = private_key

        res = hr(keys_url, method="post", headers={"X-Vault-Token": token}, params=keys, verify=verify_tls)
        data = res.json
        if res.code == 204:
            return Ok(res.code == 204, data=data)
        if res.code == 403:
            return Err("permission denied", data=data)
        return Err(res.error or "error", data=data)
    except Exception as e:
        return Err(f"exception: {e}", data=data)
