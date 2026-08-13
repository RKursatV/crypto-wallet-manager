#!/usr/bin/env python3
"""Local crypto wallet manager.

Creates and imports BIP39 HD wallets, derives Bitcoin (BIP84 native segwit)
and Ethereum (BIP44) addresses, stores secrets encrypted at rest with a
master password, and checks on-chain balances via public APIs.

Secrets are encrypted with Fernet (AES-128-CBC + HMAC) using a key derived
from the master password via scrypt. Wallet names and public addresses are
stored in plaintext so read-only commands (list, balance) never need the
password.

This tool intentionally does NOT sign or send transactions.
"""

import argparse
import base64
import getpass
import json
import os
import secrets as pysecrets
import sys
from datetime import datetime, timezone

try:
    from bip_utils import (
        Bip39MnemonicGenerator,
        Bip39MnemonicValidator,
        Bip39SeedGenerator,
        Bip39WordsNum,
        Bip44,
        Bip44Changes,
        Bip44Coins,
        Bip84,
        Bip84Coins,
        EthAddrEncoder,
        Secp256k1PrivateKey,
    )
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as exc:
    sys.exit(
        f"Missing dependency: {exc.name}. "
        "Install with: pip install -r requirements.txt"
    )

DEFAULT_STORE = os.path.join(
    os.path.expanduser("~"), ".crypto-wallet-manager", "wallets.json"
)
STORE_VERSION = 1
CHECK_PLAINTEXT = b"crypto-wallet-manager-check-v1"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1

ETH_RPC_URL = "https://ethereum-rpc.publicnode.com"
BTC_API_URL = "https://blockstream.info/api/address/{address}"

WORDS_TO_ENUM = {
    12: Bip39WordsNum.WORDS_NUM_12,
    15: Bip39WordsNum.WORDS_NUM_15,
    18: Bip39WordsNum.WORDS_NUM_18,
    21: Bip39WordsNum.WORDS_NUM_21,
    24: Bip39WordsNum.WORDS_NUM_24,
}

ETH_PATH = "m/44'/60'/0'/0/0"
BTC_PATH = "m/84'/0'/0'/0/0"


# ---------------------------------------------------------------- storage

def store_path(args):
    return os.path.abspath(args.file or os.environ.get("WALLET_MANAGER_FILE") or DEFAULT_STORE)


def load_store(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_store(path, store):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(store, fh, indent=2)
        fh.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def new_store():
    salt = pysecrets.token_bytes(16)
    return {
        "version": STORE_VERSION,
        "kdf": {
            "name": "scrypt",
            "salt": base64.b64encode(salt).decode(),
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
        },
        "check": None,  # filled in once the master password is set
        "wallets": [],
    }


def derive_fernet(store, password):
    kdf_meta = store["kdf"]
    kdf = Scrypt(
        salt=base64.b64decode(kdf_meta["salt"]),
        length=32,
        n=kdf_meta["n"],
        r=kdf_meta["r"],
        p=kdf_meta["p"],
    )
    key = kdf.derive(password.encode())
    return Fernet(base64.urlsafe_b64encode(key))


def get_password(prompt="Master password: ", confirm=False):
    env = os.environ.get("WALLET_MANAGER_PASSWORD")
    if env is not None:
        return env
    pw = getpass.getpass(prompt)
    if confirm:
        again = getpass.getpass("Confirm password: ")
        if pw != again:
            sys.exit("Passwords do not match.")
    if not pw:
        sys.exit("Empty password not allowed.")
    return pw


def unlock(store, create_if_new=False):
    """Return a Fernet for the store, verifying (or setting) the password."""
    if store["check"] is None:
        if not create_if_new:
            sys.exit("Keystore has no password set yet; create a wallet first.")
        print("Setting master password for a new keystore.")
        pw = get_password("New master password: ", confirm=True)
        fernet = derive_fernet(store, pw)
        store["check"] = fernet.encrypt(CHECK_PLAINTEXT).decode()
        return fernet
    fernet = derive_fernet(store, get_password())
    try:
        if fernet.decrypt(store["check"].encode()) != CHECK_PLAINTEXT:
            raise InvalidToken
    except InvalidToken:
        sys.exit("Wrong master password.")
    return fernet


def find_wallet(store, name):
    for wallet in store["wallets"]:
        if wallet["name"] == name:
            return wallet
    sys.exit(f"No wallet named {name!r}. Run 'list' to see wallets.")


# ---------------------------------------------------------------- derivation

def derive_addresses(mnemonic):
    seed = Bip39SeedGenerator(mnemonic).Generate()
    eth = (
        Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
        .Purpose().Coin().Account(0)
        .Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    )
    btc = (
        Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
        .Purpose().Coin().Account(0)
        .Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    )
    return {
        "eth_address": eth.PublicKey().ToAddress(),
        "btc_address": btc.PublicKey().ToAddress(),
    }


def derive_eth_private_key(mnemonic):
    seed = Bip39SeedGenerator(mnemonic).Generate()
    eth = (
        Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
        .Purpose().Coin().Account(0)
        .Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    )
    return eth.PrivateKey().Raw().ToHex()


def eth_address_from_private_key(key_hex):
    key_hex = key_hex.lower().removeprefix("0x")
    priv = Secp256k1PrivateKey.FromBytes(bytes.fromhex(key_hex))
    return EthAddrEncoder.EncodeKey(priv.PublicKey().UnderlyingObject())


# ---------------------------------------------------------------- balances

def fetch_eth_balance(address):
    import requests

    resp = requests.post(
        ETH_RPC_URL,
        json={"jsonrpc": "2.0", "method": "eth_getBalance",
              "params": [address, "latest"], "id": 1},
        timeout=15,
    )
    resp.raise_for_status()
    body = resp.json()
    if "error" in body:
        raise RuntimeError(body["error"])
    wei = int(body["result"], 16)
    return wei / 10**18


def fetch_btc_balance(address):
    import requests

    resp = requests.get(BTC_API_URL.format(address=address), timeout=15)
    resp.raise_for_status()
    stats = resp.json()["chain_stats"]
    sats = stats["funded_txo_sum"] - stats["spent_txo_sum"]
    return sats / 10**8


# ---------------------------------------------------------------- commands

def read_secret_line(prompt):
    """Read a secret from the terminal (hidden) or from piped stdin."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt).strip()
    return sys.stdin.readline().strip()


def print_wallet(wallet, verbose=False):
    print(f"  {wallet['name']}")
    print(f"    ETH: {wallet.get('eth_address', '-')}")
    print(f"    BTC: {wallet.get('btc_address', '-')}")
    if verbose:
        print(f"    type:    {wallet['type']}")
        print(f"    created: {wallet['created_at']}")
        if wallet["type"] == "mnemonic":
            print(f"    paths:   ETH {ETH_PATH}   BTC {BTC_PATH}")


def cmd_create(args):
    path = store_path(args)
    store = load_store(path) or new_store()
    if any(w["name"] == args.name for w in store["wallets"]):
        sys.exit(f"A wallet named {args.name!r} already exists.")
    fernet = unlock(store, create_if_new=True)

    mnemonic = str(Bip39MnemonicGenerator().FromWordsNumber(WORDS_TO_ENUM[args.words]))
    wallet = {
        "name": args.name,
        "type": "mnemonic",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "secret": fernet.encrypt(mnemonic.encode()).decode(),
        **derive_addresses(mnemonic),
    }
    store["wallets"].append(wallet)
    save_store(path, store)

    print(f"Created wallet {args.name!r} ({args.words} words).")
    print_wallet(wallet)
    print()
    print("Recovery phrase (write it down on paper, then clear your terminal):")
    print(f"  {mnemonic}")
    print()
    print("WARNING: anyone with this phrase controls the funds. It is stored")
    print(f"encrypted in {path}, but the paper backup is what saves you if")
    print("this machine dies. Never store it in a screenshot or cloud note.")


def cmd_import(args):
    path = store_path(args)
    store = load_store(path) or new_store()
    if any(w["name"] == args.name for w in store["wallets"]):
        sys.exit(f"A wallet named {args.name!r} already exists.")
    fernet = unlock(store, create_if_new=True)

    if args.eth_private_key:
        key_hex = read_secret_line("ETH private key (hex, input hidden): ")
        try:
            address = eth_address_from_private_key(key_hex)
        except ValueError:
            sys.exit("Not a valid secp256k1 private key.")
        wallet = {
            "name": args.name,
            "type": "eth_private_key",
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "secret": fernet.encrypt(key_hex.encode()).decode(),
            "eth_address": address,
        }
    else:
        mnemonic = read_secret_line("Recovery phrase (input hidden): ")
        if not Bip39MnemonicValidator().IsValid(mnemonic):
            sys.exit("Not a valid BIP39 mnemonic (check spelling and word count).")
        wallet = {
            "name": args.name,
            "type": "mnemonic",
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "secret": fernet.encrypt(mnemonic.encode()).decode(),
            **derive_addresses(mnemonic),
        }

    store["wallets"].append(wallet)
    save_store(path, store)
    print(f"Imported wallet {args.name!r}.")
    print_wallet(wallet)


def cmd_list(args):
    store = load_store(store_path(args))
    if not store or not store["wallets"]:
        print("No wallets yet. Create one with: wallet_manager.py create <name>")
        return
    print(f"{len(store['wallets'])} wallet(s) in {store_path(args)}:")
    for wallet in store["wallets"]:
        print_wallet(wallet)


def cmd_show(args):
    store = load_store(store_path(args))
    if not store:
        sys.exit("No keystore found.")
    print_wallet(find_wallet(store, args.name), verbose=True)


def cmd_balance(args):
    store = load_store(store_path(args))
    if not store or not store["wallets"]:
        sys.exit("No wallets to check.")
    wallets = [find_wallet(store, args.name)] if args.name else store["wallets"]
    for wallet in wallets:
        print(f"{wallet['name']}:")
        if wallet.get("eth_address"):
            try:
                eth = fetch_eth_balance(wallet["eth_address"])
                print(f"  ETH: {eth:.6f}  ({wallet['eth_address']})")
            except Exception as exc:
                print(f"  ETH: lookup failed ({exc})")
        if wallet.get("btc_address"):
            try:
                btc = fetch_btc_balance(wallet["btc_address"])
                print(f"  BTC: {btc:.8f}  ({wallet['btc_address']})")
            except Exception as exc:
                print(f"  BTC: lookup failed ({exc})")


def cmd_export(args):
    path = store_path(args)
    store = load_store(path)
    if not store:
        sys.exit("No keystore found.")
    wallet = find_wallet(store, args.name)
    fernet = unlock(store)

    print("You are about to display secret key material on screen.")
    if input("Type 'reveal' to continue: ").strip() != "reveal":
        sys.exit("Aborted.")

    secret = fernet.decrypt(wallet["secret"].encode()).decode()
    if wallet["type"] == "mnemonic":
        if args.eth_key:
            print(f"ETH private key ({ETH_PATH}):")
            print(f"  0x{derive_eth_private_key(secret)}")
        else:
            print("Recovery phrase:")
            print(f"  {secret}")
    else:
        print("ETH private key:")
        print(f"  0x{secret}")
    print("\nClear your terminal history/scrollback when done.")


def cmd_delete(args):
    path = store_path(args)
    store = load_store(path)
    if not store:
        sys.exit("No keystore found.")
    wallet = find_wallet(store, args.name)
    print(f"Deleting {wallet['name']!r} removes its encrypted secret from this")
    print("machine. Without a backup of the recovery phrase, funds are LOST.")
    if input(f"Type the wallet name ({args.name}) to confirm: ").strip() != args.name:
        sys.exit("Aborted.")
    store["wallets"].remove(wallet)
    save_store(path, store)
    print(f"Deleted wallet {args.name!r}.")


def cmd_change_password(args):
    path = store_path(args)
    store = load_store(path)
    if not store or store["check"] is None:
        sys.exit("No keystore found.")
    old_fernet = unlock(store)
    secrets_plain = [
        old_fernet.decrypt(w["secret"].encode()) for w in store["wallets"]
    ]

    new_pw = os.environ.get("WALLET_MANAGER_NEW_PASSWORD")
    if new_pw is None:
        new_pw = getpass.getpass("New master password: ")
        if new_pw != getpass.getpass("Confirm new password: "):
            sys.exit("Passwords do not match.")
    if not new_pw:
        sys.exit("Empty password not allowed.")

    store["kdf"]["salt"] = base64.b64encode(pysecrets.token_bytes(16)).decode()
    new_fernet = derive_fernet(store, new_pw)
    store["check"] = new_fernet.encrypt(CHECK_PLAINTEXT).decode()
    for wallet, plain in zip(store["wallets"], secrets_plain):
        wallet["secret"] = new_fernet.encrypt(plain).decode()
    save_store(path, store)
    print("Master password changed; all secrets re-encrypted.")


# ---------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser(
        description="Manage crypto wallets locally (BTC + ETH, encrypted at rest).",
        epilog="Keystore location: --file, $WALLET_MANAGER_FILE, or "
               f"{DEFAULT_STORE}",
    )
    parser.add_argument("--file", help="path to the keystore JSON file")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create", help="generate a new HD wallet")
    p.add_argument("name")
    p.add_argument("--words", type=int, default=24, choices=sorted(WORDS_TO_ENUM),
                   help="mnemonic length (default: 24)")
    p.set_defaults(func=cmd_create)

    p = sub.add_parser("import", help="import a recovery phrase or ETH private key")
    p.add_argument("name")
    p.add_argument("--eth-private-key", action="store_true",
                   help="import a raw ETH private key instead of a mnemonic")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("list", help="list wallets and addresses")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("show", help="show one wallet's details")
    p.add_argument("name")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("balance", help="fetch on-chain balances")
    p.add_argument("name", nargs="?", help="wallet name (default: all)")
    p.set_defaults(func=cmd_balance)

    p = sub.add_parser("export", help="reveal a wallet's secret (guarded)")
    p.add_argument("name")
    p.add_argument("--eth-key", action="store_true",
                   help="show the derived ETH private key instead of the phrase")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("delete", help="delete a wallet from the keystore")
    p.add_argument("name")
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("change-password", help="re-encrypt the keystore with a new password")
    p.set_defaults(func=cmd_change_password)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
