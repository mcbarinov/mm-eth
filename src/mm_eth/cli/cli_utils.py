import importlib.metadata


def get_version() -> str:
    return importlib.metadata.version("mm-eth")


def public_rpc_url(url: str | None) -> str:
    if not url or url == "1":
        return "https://ethereum.publicnode.com"
    if url.startswith(("http://", "https://", "ws://", "wss://")):
        return url

    match url.lower():
        case "opbnb" | "204":
            return "https://opbnb-mainnet-rpc.bnbchain.org"
        case "base" | "8453":
            return "https://mainnet.base.org"
        case "base-sepolia" | "84532":
            return "https://sepolia.base.org"
        case _:
            return url
