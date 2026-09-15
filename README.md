# crypto-wallet-manager

A local CLI for managing crypto wallets: generate BIP39 HD wallets, derive
Bitcoin (native segwit, BIP84) and Ethereum (BIP44) addresses, keep secrets
encrypted at rest, and check on-chain balances via public APIs.

It deliberately does **not** sign or send transactions — it manages keys and
watches balances only.

## Install

Requires Python 3.10+.

```sh
pipx install .            # isolated install, puts `wallet-manager` on PATH
# or
pip install .
```

For development, or to run it without installing:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt   # exact pinned versions
.venv/bin/python wallet_manager.py --help
```

## Usage

```sh
wallet-manager create savings              # generate a new 24-word wallet
wallet-manager create hot --words 12       # 12-word variant
wallet-manager list                        # names + addresses (no password needed)
wallet-manager balance                     # on-chain balances for all wallets
wallet-manager balance savings             # ... or just one
wallet-manager show savings                # details incl. derivation paths
wallet-manager import old-wallet           # import an existing recovery phrase
wallet-manager import mm --eth-private-key # import a raw ETH private key
wallet-manager export savings              # reveal the recovery phrase (guarded)
wallet-manager export savings --eth-key    # reveal derived ETH private key (guarded)
wallet-manager delete old-wallet           # remove a wallet (password + typed confirmation)
wallet-manager change-password             # re-encrypt keystore with a new password
wallet-manager verify                      # prove stored addresses match their secrets
```

The first `create`/`import` asks you to set a master password for the
keystore. Every command that touches or destroys secret material asks for
it again; `list`, `show`, and `balance` never need it.

`create` prints the new recovery phrase only when stdout is a terminal, so
it never lands in a log file or pipe by accident. Write it on paper.

## Where things live

The keystore is a single JSON file (default
`~/.crypto-wallet-manager/wallets.json`, permissions `0600`, written
atomically). Override the location with `--file <path>` or
`$WALLET_MANAGER_FILE`.

Wallet names and public addresses are plaintext; recovery phrases / private
keys are encrypted with Fernet (AES-128-CBC + HMAC-SHA256). scrypt
(N=2¹⁷, r=8, p=1 — the OWASP minimum, ~128 MiB and about half a second per
unlock) stretches your master password into 64 bytes: half becomes the
Fernet key, half an HMAC key that seals every wallet record, ciphertext
included.

That seal means anyone who edits the file — to swap your deposit addresses
for theirs, swap secrets between wallets, add or rename a wallet — is caught
the next time you enter your password, and a keystore whose seal is missing
is refused outright. `list` and `balance` skip the password, so they can't
check the seal — if the file has been somewhere you don't trust, run
`verify`, which additionally re-derives every address from its decrypted
secret.

Derivation paths: ETH `m/44'/60'/0'/0/0`, BTC `m/84'/0'/0'/0/0`.
These are the standard first-account paths, so any generated wallet can be
restored in MetaMask, Sparrow, Electrum, Ledger, etc. from its phrase.

Balance sources: `ethereum-rpc.publicnode.com` (JSON-RPC) and
`blockstream.info` (REST). Only your public addresses are sent to these
services. `balance` exits non-zero if any lookup fails.

## Limitations

- One address per wallet per chain (account 0, index 0). Funds received on
  other addresses of the same seed are not shown by `balance`.
- No BIP39 passphrase ("25th word") support.
- English BIP39 word list only.
- Keystores written by pre-release builds (format v1/v2) are not read.
  Recreate the keystore by importing each wallet from its recovery phrase.

## Automation

`$WALLET_MANAGER_PASSWORD` (and `$WALLET_MANAGER_NEW_PASSWORD` for
`change-password`) bypass the interactive prompts — meant for scripts and
tests. When stdin is not a terminal, `import` reads the phrase or key from
it, and `export`/`delete` read their confirmation from it. Don't put your
real master password in shell history or dotfiles.

## Security notes

- Write recovery phrases on paper. The encrypted file protects against
  casual file theft, not against a compromised machine or a weak password.
- `export` prints secrets to the terminal — clear scrollback afterwards.
- This is a hot-wallet tool; keep meaningful funds on hardware wallets.

## Development

```sh
pip install -e ".[dev]"
ruff check .
pytest
```

The tests never touch `~/.crypto-wallet-manager`; they run against
temporary keystores with a lowered scrypt cost. Known-answer vectors cover
BIP39 → BIP44/BIP84 derivation, and the tamper tests mutate the keystore
JSON directly.

## License

MIT — see [LICENSE](LICENSE).
