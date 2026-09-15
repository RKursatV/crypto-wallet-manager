import os
import stat

import pytest

import wallet_manager as wm
from conftest import ORIGINAL_SCRYPT_N, PASSWORD

# BIP39 / BIP44 / BIP84 reference vectors (first account, first address).
VECTOR_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
VECTOR_ETH = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
VECTOR_BTC = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
VECTOR_ETH_KEY = "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"

# Well-known test key from the web3.py docs.
RAW_KEY = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
RAW_KEY_ETH = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"


# ---------------------------------------------------------------- create / list / verify

def test_create_list_verify_roundtrip(cli, keystore):
    out = cli.ok("create", "savings", "--words", "12")
    assert "Created wallet 'savings' (12 words)" in out
    assert "recovery phrase was NOT printed" in out  # stdout is not a tty here

    out = cli.ok("list")
    assert "1 wallet(s)" in out and "savings" in out
    assert "ETH: 0x" in out and "BTC: bc1q" in out

    assert "All wallets verified" in cli.ok("verify")

    store = keystore.read()
    assert store["version"] == wm.STORE_VERSION
    assert store["kdf"]["name"] == "scrypt" and store["kdf"]["n"] == wm.SCRYPT_N
    assert isinstance(store["seal"], str) and len(store["seal"]) == 64
    assert stat.S_IMODE(os.stat(keystore.path).st_mode) == 0o600
    assert not os.path.exists(str(keystore.path) + ".tmp")


def test_create_prints_phrase_only_on_tty(cli):
    out = cli.ok("create", "hot", "--words", "12", tty_stdout=True)
    phrase = out.split("Recovery phrase")[1].splitlines()[1].strip()
    assert len(phrase.split()) == 12
    assert wm.Bip39MnemonicValidator().IsValid(phrase)

    # The printed phrase really is the stored secret.
    out = cli.ok("export", "hot", inputs=["reveal"])
    assert phrase in out


def test_export_eth_key_matches_mnemonic_wallet(cli):
    cli.ok("import", "vec", stdin=VECTOR_MNEMONIC + "\n")
    out = cli.ok("export", "vec", "--eth-key", inputs=["reveal"])
    assert f"0x{VECTOR_ETH_KEY}" in out
    assert wm.ETH_PATH in out


def test_release_kdf_cost_meets_owasp_minimum():
    assert ORIGINAL_SCRYPT_N >= 2**17
    assert (wm.SCRYPT_R, wm.SCRYPT_P) == (8, 1)


# ---------------------------------------------------------------- import

def test_import_mnemonic_known_vector_normalizes_input(cli):
    messy = "  abandon  ABANDON abandon abandon abandon abandon\tabandon " \
            "abandon abandon abandon abandon About \n"
    out = cli.ok("import", "vec", stdin=messy)
    assert VECTOR_ETH in out and VECTOR_BTC in out

    out = cli.ok("export", "vec", inputs=["reveal"])
    assert f"  {VECTOR_MNEMONIC}\n" in out  # canonical form stored
    assert "All wallets verified" in cli.ok("verify")


def test_import_rejects_invalid_mnemonic(cli):
    msg = cli.fail("import", "bad", stdin="foo bar baz\n")
    assert "Not a valid BIP39 mnemonic" in msg


@pytest.mark.parametrize("raw", [RAW_KEY, "0x" + RAW_KEY, RAW_KEY.upper(), f"  0X{RAW_KEY}\n"])
def test_import_eth_private_key_known_vector(cli, raw):
    out = cli.ok("import", "mm", "--eth-private-key", stdin=raw)
    assert RAW_KEY_ETH in out and "BTC: -" in out

    out = cli.ok("export", "mm", inputs=["reveal"])
    assert f"  0x{RAW_KEY}\n" in out
    assert "0x0x" not in out
    assert "All wallets verified" in cli.ok("verify")


@pytest.mark.parametrize("raw", ["zz", "abcd", "00" * 32, "ff" * 32, RAW_KEY[:-2], ""])
def test_import_rejects_invalid_private_key(cli, raw):
    msg = cli.fail("import", "bad", "--eth-private-key", stdin=raw + "\n")
    assert "Not a valid secp256k1 private key" in msg


def test_duplicate_name_rejected_before_password(cli, monkeypatch):
    cli.ok("create", "a", "--words", "12")
    monkeypatch.setenv("WALLET_MANAGER_PASSWORD", "irrelevant")
    assert "already exists" in cli.fail("create", "a")
    assert "already exists" in cli.fail("import", "a", stdin=VECTOR_MNEMONIC)


# ---------------------------------------------------------------- password handling

def test_wrong_password(cli, monkeypatch):
    cli.ok("create", "a", "--words", "12")
    monkeypatch.setenv("WALLET_MANAGER_PASSWORD", "not it")
    assert cli.fail("verify") == "Wrong master password."
    assert cli.fail("export", "a", inputs=["reveal"]) == "Wrong master password."


def test_empty_env_password_refused(cli, monkeypatch):
    monkeypatch.setenv("WALLET_MANAGER_PASSWORD", "")
    assert "set but empty" in cli.fail("create", "a")


def test_read_only_commands_need_no_password(cli, monkeypatch):
    cli.ok("create", "a", "--words", "12")
    monkeypatch.delenv("WALLET_MANAGER_PASSWORD")  # getpass would now raise
    assert "a" in cli.ok("list")
    out = cli.ok("show", "a")
    assert "type:    mnemonic" in out and wm.BTC_PATH in out


def test_change_password_reencrypts_and_rotates_kdf(cli, keystore, monkeypatch):
    cli.ok("import", "vec", stdin=VECTOR_MNEMONIC)
    before = keystore.read()

    monkeypatch.setenv("WALLET_MANAGER_NEW_PASSWORD", "a much better passphrase")
    assert "all secrets re-encrypted" in cli.ok("change-password")

    after = keystore.read()
    assert after["kdf"]["salt"] != before["kdf"]["salt"]
    assert after["wallets"][0]["secret"] != before["wallets"][0]["secret"]
    assert after["seal"] != before["seal"]

    assert cli.fail("verify") == "Wrong master password."  # old password
    monkeypatch.setenv("WALLET_MANAGER_PASSWORD", "a much better passphrase")
    assert "All wallets verified" in cli.ok("verify")
    assert VECTOR_MNEMONIC in cli.ok("export", "vec", inputs=["reveal"])


def test_change_password_refuses_empty(cli, monkeypatch):
    cli.ok("create", "a", "--words", "12")
    monkeypatch.setenv("WALLET_MANAGER_NEW_PASSWORD", "")
    assert "set but empty" in cli.fail("change-password")


# ---------------------------------------------------------------- tamper detection

@pytest.fixture
def two_wallets(cli):
    cli.ok("import", "vec", stdin=VECTOR_MNEMONIC)
    cli.ok("import", "mm", "--eth-private-key", stdin=RAW_KEY)


def _swap_address(store):
    store["wallets"][0]["eth_address"] = "0x000000000000000000000000000000000000dEaD"


def _strip_seal(store):
    store["seal"] = None


def _swap_secrets(store):
    a, b = store["wallets"]
    a["secret"], b["secret"] = b["secret"], a["secret"]


def _rename(store):
    store["wallets"][0]["name"] = "vec2"


def _add_wallet(store):
    store["wallets"].append(dict(store["wallets"][1], name="clone"))


TAMPERINGS = [_swap_address, _strip_seal, _swap_secrets, _rename, _add_wallet]


@pytest.mark.parametrize("mutate", TAMPERINGS)
def test_tampered_keystore_refused_by_every_unlocking_command(cli, keystore, two_wallets, mutate):
    keystore.edit(mutate)
    name = keystore.read()["wallets"][0]["name"]
    for argv, kw in [
        (("verify",), {}),
        (("export", name), {"inputs": ["reveal"]}),
        (("delete", name), {"inputs": [name]}),
        (("change-password",), {}),
        (("create", "new"), {}),
    ]:
        assert cli.fail(*argv, **kw).startswith("TAMPER WARNING"), argv


def test_downgraded_version_is_refused(cli, keystore, two_wallets):
    keystore.edit(lambda s: s.__setitem__("version", 2))
    msg = cli.fail("list")
    assert "format v2 is not supported" in msg and "expects v3" in msg


def test_corrupt_secret_reported_cleanly(cli, keystore, two_wallets, monkeypatch):
    # Re-seal a store whose ciphertext was replaced, simulating corruption
    # that slipped past the seal (e.g. an old backup's token under a new key).
    store = keystore.read()
    keys = wm.derive_keys(store, PASSWORD)
    store["wallets"][0]["secret"] = wm.Fernet.generate_key().decode()
    wm.seal_store(store, keys)
    keystore.write(store)
    assert "corrupt" in cli.fail("export", "vec", inputs=["reveal"])


def test_verify_catches_type_confusion_that_the_seal_would_not(cli, keystore, two_wallets):
    # Simulate an attacker who can forge the seal: verify must still notice.
    store = keystore.read()
    keys = wm.derive_keys(store, PASSWORD)
    store["wallets"][0]["type"] = "eth_private_key"
    _swap_address(store)
    wm.seal_store(store, keys)
    keystore.write(store)
    msg = cli.fail("verify")
    assert "1 wallet(s) failed verification" in msg


# ---------------------------------------------------------------- malformed files

@pytest.mark.parametrize("content, expected", [
    ("{ not json", "Cannot read keystore"),
    ("[]", "is not a wallet-manager keystore"),
    ('{"version": 3, "kdf": {}, "check": null}', "is not a wallet-manager keystore"),
    ('{"version": 99, "kdf": {}, "check": null, "wallets": []}', "format v99 is not supported"),
    ('{"version": 3, "kdf": {}, "check": "x", "wallets": [{"name": "a"}]}',
     "malformed wallet record"),
    ('{"version": 3, "kdf": {}, "check": null, '
     '"wallets": [{"name": "a", "type": "mnemonic", "secret": "x"}]}',
     "no master password"),
])
def test_unusable_keystore_files(cli, keystore, content, expected):
    keystore.path.write_text(content)
    assert expected in cli.fail("list")


def test_missing_keystore(cli):
    assert "No wallets yet" in cli.ok("list")
    assert cli.fail("show", "a") == "No keystore found."
    assert cli.fail("verify") == "No keystore found."
    assert cli.fail("balance") == "No wallets to check."


def test_file_flag_overrides_env(cli, tmp_path):
    other = tmp_path / "other.json"
    cli.ok("--file", str(other), "create", "x", "--words", "12")
    assert other.exists()
    assert "No wallets yet" in cli.ok("list")  # env-pointed store untouched


# ---------------------------------------------------------------- guarded commands

def test_export_requires_reveal(cli):
    cli.ok("create", "a", "--words", "12")
    assert cli.fail("export", "a", inputs=["no"]) == "Aborted."
    assert "No wallet named 'zzz'" in cli.fail("export", "zzz")


def test_delete_requires_exact_name(cli, keystore, two_wallets):
    assert cli.fail("delete", "vec", inputs=["ve"]) == "Aborted."
    assert len(keystore.read()["wallets"]) == 2

    assert "Deleted wallet 'vec'" in cli.ok("delete", "vec", inputs=["vec"])
    store = keystore.read()
    assert [w["name"] for w in store["wallets"]] == ["mm"]
    assert "All wallets verified" in cli.ok("verify")  # re-sealed after delete


# ---------------------------------------------------------------- balances (network mocked)

class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload, self.status = payload, status

    def raise_for_status(self):
        if self.status >= 400:
            raise RuntimeError(f"HTTP {self.status}")

    def json(self):
        return self.payload


def test_balance_formats_and_reports_failures(cli, monkeypatch, two_wallets):
    calls = []

    def fake_post(url, json, timeout):
        calls.append(("post", url, json["params"][0]))
        if json["params"][0] == RAW_KEY_ETH:
            return FakeResponse({"error": {"code": -32000, "message": "boom"}})
        return FakeResponse({"result": hex(1_500_000_000_000_000_000)})

    def fake_get(url, timeout):
        calls.append(("get", url, None))
        return FakeResponse({"chain_stats": {"funded_txo_sum": 150_000_000,
                                             "spent_txo_sum": 50_000_000}})

    monkeypatch.setattr(wm.requests, "post", fake_post)
    monkeypatch.setattr(wm.requests, "get", fake_get)

    code, out = cli.run("balance")
    assert code == 1  # one lookup failed
    assert f"ETH: 1.500000  ({VECTOR_ETH})" in out
    assert f"BTC: 1.00000000  ({VECTOR_BTC})" in out
    assert "ETH: lookup failed" in out and "boom" in out
    # Only public addresses ever leave the machine.
    assert [c[2] for c in calls if c[0] == "post"] == [VECTOR_ETH, RAW_KEY_ETH]
    assert calls[1] == ("get", wm.BTC_API_URL.format(address=VECTOR_BTC), None)

    out = cli.ok("balance", "vec")
    assert RAW_KEY_ETH not in out


# ---------------------------------------------------------------- misc CLI

def test_version_flag(cli):
    code, out = cli.run("--version")
    assert code == 0 and out.strip() == f"wallet-manager {wm.__version__}"


def test_keyboard_interrupt_exits_cleanly(cli, monkeypatch):
    def boom(args):
        raise KeyboardInterrupt

    monkeypatch.setattr(wm, "cmd_list", boom)  # build_parser looks it up at call time
    assert cli.fail("list").strip() == "Aborted."
