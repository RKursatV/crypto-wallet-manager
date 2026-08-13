# crypto-wallet-manager

A local CLI for managing crypto wallets: generate BIP39 HD wallets, derive
Bitcoin (native segwit, BIP84) and Ethereum (BIP44) addresses, keep secrets
encrypted at rest, and check on-chain balances via public APIs.

It deliberately does **not** sign or send transactions — it manages keys and
watches balances only.

## Setup

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Usage

```sh
alias wm=".venv/bin/python wallet_manager.py"

wm create savings              # generate a new 24-word wallet
wm create hot --words 12       # 12-word variant
wm list                        # names + addresses (no password needed)
wm balance                     # on-chain balances for all wallets
wm balance savings             # ... or just one
wm show savings                # details incl. derivation paths
wm import old-wallet           # import an existing recovery phrase
wm import mm --eth-private-key # import a raw ETH private key
wm export savings              # reveal the recovery phrase (guarded)
wm export savings --eth-key    # reveal derived ETH private key (guarded)
wm delete old-wallet           # remove a wallet (typed confirmation)
wm change-password             # re-encrypt keystore with a new password
```

The first `create`/`import` asks you to set a master password for the
keystore. Every command that touches secret material asks for it again;
`list`, `show`, and `balance` never need it.

## Where things live

The keystore is a single JSON file (default
`~/.crypto-wallet-manager/wallets.json`, permissions `0600`). Wallet names
and public addresses are plaintext; recovery phrases / private keys are
encrypted with Fernet (AES-128-CBC + HMAC-SHA256) under a key derived from
your master password with scrypt (n=32768, r=8, p=1).

Override the location with `--file <path>` or `$WALLET_MANAGER_FILE`.

Derivation paths: ETH `m/44'/60'/0'/0/0`, BTC `m/84'/0'/0'/0/0`.
These are the standard first-account paths, so any generated wallet can be
restored in MetaMask, Sparrow, Electrum, Ledger, etc. from its phrase.

Balance sources: `ethereum-rpc.publicnode.com` (JSON-RPC) and
`blockstream.info` (REST). Only your public addresses are sent to these
services.

## Automation

`$WALLET_MANAGER_PASSWORD` (and `$WALLET_MANAGER_NEW_PASSWORD` for
`change-password`) bypass the interactive prompts — meant for scripts and
tests. Don't put your real master password in shell history or dotfiles.

## Security notes

- Write recovery phrases on paper. The encrypted file protects against
  casual file theft, not against a compromised machine or a weak password.
- `export` prints secrets to the terminal — clear scrollback afterwards.
- This is a hot-wallet tool; keep meaningful funds on hardware wallets.
