#!/usr/bin/env python3
"""Local crypto wallet manager.

Creates and imports BIP39 HD wallets, derives Bitcoin (BIP84 native segwit)
and Ethereum (BIP44) addresses, stores secrets encrypted at rest with a
master password, and checks on-chain balances via public APIs.

Secrets are encrypted with Fernet (AES-128-CBC + HMAC) using a key derived
from the master password via scrypt. Wallet names and public addresses are
stored in plaintext so read-only commands (list, balance) never need the
password. Every wallet record (including its ciphertext) is sealed with an
HMAC so edits to the file are detected the next time it is unlocked.

This tool intentionally does NOT sign or send transactions.
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets as pysecrets
import sys
from collections import namedtuple
from datetime import datetime, timezone

try:
    import requests
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
        "Install with: pip install . (or pip install -r requirements.txt)"
    )

__version__ = "0.1.0"

DEFAULT_STORE = os.path.join(
    os.path.expanduser("~"), ".crypto-wallet-manager", "wallets.json"
)

# Keystore format version. Versions 1 and 2 were pre-release formats (no
# seal / seal over public metadata only) and are rejected: recreate the
# keystore by importing each wallet from its recovery phrase.
STORE_VERSION = 3
CHECK_PLAINTEXT = b"crypto-wallet-manager-check"
# OWASP minimum for scrypt (2**17, r=8, p=1 = 128 MiB, ~0.5 s). Stored per
# keystore; 'change-password' re-derives with the current parameters.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**17, 8, 1

ETH_RPC_URL = "https://ethereum-rpc.publicnode.com"
BTC_API_URL = "https://blockstream.info/api/address/{address}"
HTTP_TIMEOUT = 15

WORDS_TO_ENUM = {
    12: Bip39WordsNum.WORDS_NUM_12,
    15: Bip39WordsNum.WORDS_NUM_15,
    18: Bip39WordsNum.WORDS_NUM_18,
    21: Bip39WordsNum.WORDS_NUM_21,
    24: Bip39WordsNum.WORDS_NUM_24,
}

ETH_PATH = "m/44'/60'/0'/0/0"
BTC_PATH = "m/84'/0'/0'/0/0"

TAMPER_MESSAGE = (
    "TAMPER WARNING: the wallet records in the keystore do not match the\n"
    "seal written at the last save (or the seal is missing). Someone may\n"
    "have edited the file to swap in their own addresses. Do not send funds\n"
    "to any address it shows; restore the keystore from a trusted backup."
)


# ---------------------------------------------------------------- storage

def store_path(args):
    return os.path.abspath(
        args.file or os.environ.get("WALLET_MANAGER_FILE") or DEFAULT_STORE
    )


def validate_store(store, path):
    """Exit with a clear message if the JSON is not a keystore we can use."""
    if (
        not isinstance(store, dict)
        or not isinstance(store.get("kdf"), dict)
        or not isinstance(store.get("wallets"), list)
        or "check" not in store
    ):
        sys.exit(f"{path} is not a wallet-manager keystore.")
    version = store.get("version")
    if version != STORE_VERSION:
        sys.exit(
            f"Keystore format v{version} is not supported by wallet-manager "
            f"{__version__} (expects v{STORE_VERSION}). Pre-release keystores\n"
            "must be recreated: import each wallet from its recovery phrase."
        )
    for wallet in store["wallets"]:
        if not isinstance(wallet, dict) or not all(
            isinstance(wallet.get(k), str) for k in ("name", "type", "secret")
        ):
            sys.exit(f"{path} contains a malformed wallet record.")
    if store["check"] is None and store["wallets"]:
        # Nothing could have encrypted those secrets; don't let 'create' set a
        # password over them and seal records nobody can vouch for.
        sys.exit(f"{path} has wallet records but no master password; refusing.")


def load_store(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            store = json.load(fh)
    except (OSError, ValueError) as exc:
        sys.exit(f"Cannot read keystore {path}: {exc}")
    validate_store(store, path)
    return store


def save_store(path, store):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(store, fh, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())  # a lost mnemonic is unrecoverable; be sure
    os.replace(tmp, path)


def new_kdf_params():
    return {
        "name": "scrypt",
        "salt": base64.b64encode(pysecrets.token_bytes(16)).decode(),
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
    }


def new_store():
    return {
        "version": STORE_VERSION,
        "kdf": new_kdf_params(),
        "check": None,  # filled in once the master password is set
        "seal": None,  # HMAC over the wallet records, set on every save
        "wallets": [],
    }


Keys = namedtuple("Keys", ["fernet", "mac"])


def derive_keys(store, password):
    kdf_meta = store["kdf"]
    kdf = Scrypt(
        salt=base64.b64decode(kdf_meta["salt"]),
        length=64,
        n=kdf_meta["n"],
        r=kdf_meta["r"],
        p=kdf_meta["p"],
    )
    key = kdf.derive(password.encode())
    return Keys(Fernet(base64.urlsafe_b64encode(key[:32])), key[32:])


def compute_seal(store, mac_key):
    """HMAC over the canonical JSON of every wallet record (ciphertext too).

    Covering the ciphertext means secrets cannot be swapped between wallets
    or replaced with a token from another keystore that shares the password.
    """
    canonical = json.dumps(store["wallets"], sort_keys=True,
                           separators=(",", ":")).encode()
    return hmac.new(mac_key, canonical, hashlib.sha256).hexdigest()


def seal_store(store, keys):
    """Seal the wallet records so file tampering is detected at next unlock."""
    store["seal"] = compute_seal(store, keys.mac)


def get_password(prompt="Master password: ", confirm=False,
                 env_var="WALLET_MANAGER_PASSWORD"):
    env = os.environ.get(env_var)
    if env is not None:
        if not env:
            sys.exit(f"{env_var} is set but empty; refusing.")
        return env
    pw = getpass.getpass(prompt)
    if not pw:
        sys.exit("Empty password not allowed.")
    if confirm:
        if pw != getpass.getpass("Confirm password: "):
            sys.exit("Passwords do not match.")
        if len(pw) < 8:
            print("WARNING: short master password. Anyone who copies the")
            print("keystore file can brute-force it offline; use a longer one.")
    return pw


def unlock(store, create_if_new=False):
    """Return Keys for the store, verifying (or setting) the password.

    Also checks the tamper seal; a missing or mismatched seal is fatal.
    """
    if store["check"] is None:
        if not create_if_new:
            sys.exit("Keystore has no password set yet; create a wallet first.")
        print("Setting master password for a new keystore.")
        keys = derive_keys(store, get_password("New master password: ", confirm=True))
        store["check"] = keys.fernet.encrypt(CHECK_PLAINTEXT).decode()
        return keys
    keys = derive_keys(store, get_password())
    try:
        if keys.fernet.decrypt(store["check"].encode()) != CHECK_PLAINTEXT:
            raise InvalidToken
    except InvalidToken:
        sys.exit("Wrong master password.")
    seal = store.get("seal")
    if not isinstance(seal, str) or not hmac.compare_digest(
        compute_seal(store, keys.mac), seal
    ):
        sys.exit(TAMPER_MESSAGE)
    return keys


def decrypt_secret(keys, wallet):
    try:
        return keys.fernet.decrypt(wallet["secret"].encode()).decode()
    except (InvalidToken, UnicodeDecodeError):
        sys.exit(
            f"The encrypted secret of wallet {wallet['name']!r} is corrupt or\n"
            "was not encrypted with this keystore's password. Restore the\n"
            "keystore from a trusted backup."
        )


def find_wallet(store, name):
    for wallet in store["wallets"]:
        if wallet["name"] == name:
            return wallet
    sys.exit(f"No wallet named {name!r}. Run 'list' to see wallets.")


# ---------------------------------------------------------------- derivation

def normalize_mnemonic(mnemonic):
    """Collapse whitespace and case so the stored phrase is canonical."""
    return " ".join(mnemonic.lower().split())


def normalize_private_key_hex(key_hex):
    key_hex = key_hex.strip().lower().removeprefix("0x")
    if len(key_hex) != 64:
        raise ValueError("expected 32 bytes (64 hex characters)")
    bytes.fromhex(key_hex)  # raises ValueError on non-hex input
    return key_hex


def _eth_node(seed):
    return (
        Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
        .Purpose().Coin().Account(0)
        .Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    )


def _btc_node(seed):
    return (
        Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
        .Purpose().Coin().Account(0)
        .Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    )


def derive_addresses(mnemonic):
    seed = Bip39SeedGenerator(mnemonic).Generate()
    return {
        "eth_address": _eth_node(seed).PublicKey().ToAddress(),
        "btc_address": _btc_node(seed).PublicKey().ToAddress(),
    }


def derive_eth_private_key(mnemonic):
    seed = Bip39SeedGenerator(mnemonic).Generate()
    return _eth_node(seed).PrivateKey().Raw().ToHex()


def eth_address_from_private_key(key_hex):
    priv = Secp256k1PrivateKey.FromBytes(bytes.fromhex(normalize_private_key_hex(key_hex)))
    return EthAddrEncoder.EncodeKey(priv.PublicKey())


def derived_addresses_for(wallet, secret):
    """Addresses that the wallet's decrypted secret actually controls."""
    if wallet["type"] == "mnemonic":
        return derive_addresses(secret)
    if wallet["type"] == "eth_private_key":
        return {"eth_address": eth_address_from_private_key(secret)}
    raise ValueError(f"unknown wallet type {wallet['type']!r}")


# ---------------------------------------------------------------- balances

def fetch_eth_balance(address):
    resp = requests.post(
        ETH_RPC_URL,
        json={"jsonrpc": "2.0", "method": "eth_getBalance",
              "params": [address, "latest"], "id": 1},
        timeout=HTTP_TIMEOUT,
    )
    resp.raise_for_status()
    body = resp.json()
    if "error" in body:
        raise RuntimeError(body["error"])
    wei = int(body["result"], 16)
    return wei / 10**18


def fetch_btc_balance(address):
    resp = requests.get(BTC_API_URL.format(address=address), timeout=HTTP_TIMEOUT)
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
        print(f"    created: {wallet.get('created_at', '-')}")
        if wallet["type"] == "mnemonic":
            print(f"    paths:   ETH {ETH_PATH}   BTC {BTC_PATH}")


def new_wallet_record(name, wallet_type, keys, secret, addresses):
    return {
        "name": name,
        "type": wallet_type,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "secret": keys.fernet.encrypt(secret.encode()).decode(),
        **addresses,
    }


def open_store_for_new_wallet(args):
    path = store_path(args)
    store = load_store(path) or new_store()
    if any(w["name"] == args.name for w in store["wallets"]):
        sys.exit(f"A wallet named {args.name!r} already exists.")
    return path, store, unlock(store, create_if_new=True)


def cmd_create(args):
    path, store, keys = open_store_for_new_wallet(args)

    mnemonic = str(Bip39MnemonicGenerator().FromWordsNumber(WORDS_TO_ENUM[args.words]))
    wallet = new_wallet_record(args.name, "mnemonic", keys, mnemonic,
                               derive_addresses(mnemonic))
    store["wallets"].append(wallet)
    seal_store(store, keys)
    save_store(path, store)

    print(f"Created wallet {args.name!r} ({args.words} words).")
    print_wallet(wallet)
    print()
    if sys.stdout.isatty():
        print("Recovery phrase (write it down on paper, then clear your terminal):")
        print(f"  {mnemonic}")
        print()
        print("WARNING: anyone with this phrase controls the funds. It is stored")
        print(f"encrypted in {path}, but the paper backup is what saves you if")
        print("this machine dies. Never store it in a screenshot or cloud note.")
    else:
        print("stdout is not a terminal, so the recovery phrase was NOT printed")
        print("(it would have been captured by the file or pipe receiving this")
        print("output). Run 'export' in an interactive terminal to back it up.")


def cmd_import(args):
    path, store, keys = open_store_for_new_wallet(args)

    if args.eth_private_key:
        try:
            key_hex = normalize_private_key_hex(
                read_secret_line("ETH private key (hex, input hidden): ")
            )
            address = eth_address_from_private_key(key_hex)
        except ValueError:
            sys.exit("Not a valid secp256k1 private key.")
        wallet = new_wallet_record(args.name, "eth_private_key", keys, key_hex,
                                   {"eth_address": address})
    else:
        mnemonic = normalize_mnemonic(read_secret_line("Recovery phrase (input hidden): "))
        if not Bip39MnemonicValidator().IsValid(mnemonic):
            sys.exit("Not a valid BIP39 mnemonic (check spelling and word count).")
        wallet = new_wallet_record(args.name, "mnemonic", keys, mnemonic,
                                   derive_addresses(mnemonic))

    store["wallets"].append(wallet)
    seal_store(store, keys)
    save_store(path, store)
    print(f"Imported wallet {args.name!r}.")
    print_wallet(wallet)


def cmd_list(args):
    store = load_store(store_path(args))
    if not store or not store["wallets"]:
        print("No wallets yet. Create one with: wallet-manager create <name>")
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
    failures = 0
    for wallet in wallets:
        print(f"{wallet['name']}:")
        if wallet.get("eth_address"):
            try:
                eth = fetch_eth_balance(wallet["eth_address"])
                print(f"  ETH: {eth:.6f}  ({wallet['eth_address']})")
            except Exception as exc:  # network/API errors: report, keep going
                failures += 1
                print(f"  ETH: lookup failed ({exc})")
        if wallet.get("btc_address"):
            try:
                btc = fetch_btc_balance(wallet["btc_address"])
                print(f"  BTC: {btc:.8f}  ({wallet['btc_address']})")
            except Exception as exc:
                failures += 1
                print(f"  BTC: lookup failed ({exc})")
    if failures:
        sys.exit(1)


def cmd_export(args):
    path = store_path(args)
    store = load_store(path)
    if not store:
        sys.exit("No keystore found.")
    wallet = find_wallet(store, args.name)
    keys = unlock(store)

    print("You are about to display secret key material on screen.")
    if input("Type 'reveal' to continue: ").strip() != "reveal":
        sys.exit("Aborted.")

    secret = decrypt_secret(keys, wallet)
    if wallet["type"] == "mnemonic":
        if args.eth_key:
            print(f"ETH private key ({ETH_PATH}):")
            print(f"  0x{derive_eth_private_key(secret)}")
        else:
            print("Recovery phrase:")
            print(f"  {secret}")
    else:
        print("ETH private key:")
        print(f"  0x{secret.removeprefix('0x')}")
    print("\nClear your terminal history/scrollback when done.")


def cmd_delete(args):
    path = store_path(args)
    store = load_store(path)
    if not store:
        sys.exit("No keystore found.")
    wallet = find_wallet(store, args.name)
    keys = unlock(store)
    print(f"Deleting {wallet['name']!r} removes its encrypted secret from this")
    print("machine. Without a backup of the recovery phrase, funds are LOST.")
    if input(f"Type the wallet name ({args.name}) to confirm: ").strip() != args.name:
        sys.exit("Aborted.")
    store["wallets"].remove(wallet)
    seal_store(store, keys)
    save_store(path, store)
    print(f"Deleted wallet {args.name!r}.")


def cmd_change_password(args):
    path = store_path(args)
    store = load_store(path)
    if not store or store["check"] is None:
        sys.exit("No keystore found.")
    old_keys = unlock(store)
    secrets_plain = [decrypt_secret(old_keys, w) for w in store["wallets"]]

    new_pw = get_password("New master password: ", confirm=True,
                          env_var="WALLET_MANAGER_NEW_PASSWORD")

    store["kdf"] = new_kdf_params()  # fresh salt and current cost parameters
    new_keys = derive_keys(store, new_pw)
    store["check"] = new_keys.fernet.encrypt(CHECK_PLAINTEXT).decode()
    for wallet, plain in zip(store["wallets"], secrets_plain, strict=True):
        wallet["secret"] = new_keys.fernet.encrypt(plain.encode()).decode()
    seal_store(store, new_keys)
    save_store(path, store)
    print("Master password changed; all secrets re-encrypted.")


def cmd_verify(args):
    path = store_path(args)
    store = load_store(path)
    if not store or store["check"] is None:
        sys.exit("No keystore found.")
    keys = unlock(store)  # also checks the seal

    failures = 0
    for wallet in store["wallets"]:
        secret = decrypt_secret(keys, wallet)
        try:
            derived = derived_addresses_for(wallet, secret)
        except ValueError as exc:
            failures += 1
            print(f"  {wallet['name']}: INVALID — secret does not match its "
                  f"wallet type ({exc})")
            continue
        bad = [coin for coin, addr in derived.items() if wallet.get(coin) != addr]
        if bad:
            failures += 1
            print(f"  {wallet['name']}: MISMATCH on {', '.join(bad)} — the "
                  "stored address does NOT belong to this wallet's secret!")
        else:
            print(f"  {wallet['name']}: OK")

    if failures:
        sys.exit(f"{failures} wallet(s) failed verification. Do not send funds "
                 "to the addresses this keystore shows.")
    print("All wallets verified: stored addresses match their secrets.")


# ---------------------------------------------------------------- main

def build_parser():
    parser = argparse.ArgumentParser(
        prog="wallet-manager",
        description="Manage crypto wallets locally (BTC + ETH, encrypted at rest).",
        epilog="Keystore location: --file, $WALLET_MANAGER_FILE, or "
               f"{DEFAULT_STORE}",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
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

    p = sub.add_parser("change-password",
                       help="re-encrypt the keystore with a new password")
    p.set_defaults(func=cmd_change_password)

    p = sub.add_parser("verify",
                       help="check stored addresses against decrypted secrets")
    p.set_defaults(func=cmd_verify)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except KeyboardInterrupt:
        sys.exit("\nAborted.")


if __name__ == "__main__":
    main()
