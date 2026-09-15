import builtins
import io
import json
import sys

import pytest

import wallet_manager as wm

# Captured before any test lowers it, so the "release default" can be asserted.
ORIGINAL_SCRYPT_N = wm.SCRYPT_N

PASSWORD = "correct horse battery staple"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """scrypt at the release cost takes ~0.5 s per unlock; tests don't need that."""
    monkeypatch.setattr(wm, "SCRYPT_N", 2**10)


@pytest.fixture(autouse=True)
def isolated_keystore(tmp_path, monkeypatch):
    path = tmp_path / "wallets.json"
    monkeypatch.setenv("WALLET_MANAGER_FILE", str(path))
    monkeypatch.setenv("WALLET_MANAGER_PASSWORD", PASSWORD)
    monkeypatch.delenv("WALLET_MANAGER_NEW_PASSWORD", raising=False)
    # Any prompt that slips past the env vars must fail loudly, not hang.
    monkeypatch.setattr(wm.getpass, "getpass", _no_prompt)
    return path


def _no_prompt(prompt=""):
    raise AssertionError(f"unexpected interactive prompt: {prompt!r}")


class Cli:
    """Run wallet_manager.main() in-process and capture its output."""

    def __init__(self, capsys, monkeypatch):
        self._capsys = capsys
        self._monkeypatch = monkeypatch

    def run(self, *argv, stdin="", inputs=(), tty_stdout=False):
        stream = io.StringIO(stdin)  # isatty() -> False: secrets read from the pipe
        self._monkeypatch.setattr(sys, "stdin", stream)
        answers = list(inputs)
        self._monkeypatch.setattr(builtins, "input", lambda prompt="": answers.pop(0))
        if tty_stdout:
            self._monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        code = 0
        try:
            wm.main(list(argv))
        except SystemExit as exc:
            code = exc.code
        out = self._capsys.readouterr().out
        return code, out

    def ok(self, *argv, **kw):
        code, out = self.run(*argv, **kw)
        assert code in (0, None), f"exit {code!r}\n{out}"
        return out

    def fail(self, *argv, **kw):
        code, out = self.run(*argv, **kw)
        assert code not in (0, None), f"expected failure but exited 0\n{out}"
        return code if isinstance(code, str) else out


@pytest.fixture
def cli(capsys, monkeypatch):
    return Cli(capsys, monkeypatch)


@pytest.fixture
def keystore(isolated_keystore):
    """Read/write access to the raw keystore JSON for tamper tests."""

    class Keystore:
        path = isolated_keystore

        def read(self):
            return json.loads(self.path.read_text())

        def write(self, store):
            self.path.write_text(json.dumps(store))

        def edit(self, fn):
            store = self.read()
            fn(store)
            self.write(store)

    return Keystore()
