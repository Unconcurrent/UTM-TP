import json
from dataclasses import asdict
from pathlib import Path

import pytest

from arsenal.windows.inventar import (
    Eveniment,
    Inventar,
    Proces,
    evenimente_din_json,
    main,
    procese_din_json,
)

START = Path(__file__).parent / "start"


def test_proces_din_temp_e_suspect():
    p = Proces(1, "x.exe", "ana", r"C:\Users\ana\AppData\Local\Temp\x.exe")
    assert p.e_suspect() is True


def test_proces_din_windows_nu_e_suspect():
    p = Proces(2, "svchost.exe", "SYSTEM", r"C:\Windows\System32\svchost.exe")
    assert p.e_suspect() is False


def test_proces_roaming_si_egalitate():
    p = Proces(3, "x.exe", "ana", r"C:\Users\ana\AppData\Roaming\x.exe")
    assert p.e_suspect() is True
    assert p == Proces(**asdict(p))
    assert p != Proces(4, p.nume, p.user, p.cale)


def test_evenimente_si_explicatii():
    for id, fragment in ((4625, "brute force"), (1102, "șters"), (7045, "serviciu")):
        e = Eveniment(id, "info", "Security", "ana", "mesaj")
        assert e.e_suspect() is True
        assert fragment in e.explica()
    critic = Eveniment(9999, "critical", "System", "SYSTEM", "mesaj")
    normal = Eveniment(4624, "info", "Security", "ana", "mesaj")
    assert critic.e_suspect() is True
    assert critic.explica() == "Eveniment critic."
    assert normal.e_suspect() is False
    assert normal.explica() == "Alt eveniment."
    assert normal == Eveniment(**asdict(normal))


def test_inventar_capturi_si_scor():
    inv = Inventar.din_json(START / "procese.json")
    assert len(inv) == 7
    assert inv.procese == procese_din_json(START / "procese.json")
    assert [p.pid for p in inv.suspecte()] == [3120, 3890]
    assert inv.pe_user() == {
        "SYSTEM": ["System", "svchost.exe"],
        "ana": ["explorer.exe", "chrome.exe", "update.exe", "powershell.exe", "svch0st.exe"],
    }
    assert inv.scor() == 2
    inv.evenimente = evenimente_din_json(START / "evenimente.json")
    assert len(inv.evenimente) == 8
    assert [e.id for e in inv.evenimente if e.e_suspect()] == [4625, 4625, 4625, 7045, 1102]
    assert inv.scor() == 7
    gol = Inventar([])
    assert len(gol) == 0
    assert gol.suspecte() == []
    assert gol.pe_user() == {}
    assert gol.scor() == 0
    assert gol.evenimente == []


def test_cli_text_si_json(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["inventar", str(START)])
    assert main() == 0
    text = capsys.readouterr()
    assert text.err == ""
    assert text.out == (
        "Procese: 7 | suspecte: 2\n"
        "  [3120] update.exe (ana) C:\\Users\\ana\\AppData\\Local\\Temp\\update.exe\n"
        "  [3890] svch0st.exe (ana) C:\\Users\\ana\\AppData\\Roaming\\svch0st.exe\n"
        "Evenimente: 8 | alarma: 5\n"
        "  4625 [warning] administrator: An account failed to log on\n"
        "  4625 [warning] administrator: An account failed to log on\n"
        "  4625 [warning] administrator: An account failed to log on\n"
        "  7045 [warning] SYSTEM: A service was installed: WinUpdateSvc\n"
        "  1102 [critical] administrator: The audit log was cleared\n"
    )
    monkeypatch.setattr("sys.argv", ["inventar", str(START), "--json"])
    assert main() == 0
    rezultat = capsys.readouterr()
    assert rezultat.err == ""
    assert json.loads(rezultat.out) == {
        "procese": [asdict(p) for p in procese_din_json(START / "procese.json") if p.e_suspect()],
        "evenimente": [asdict(e) for e in evenimente_din_json(START / "evenimente.json") if e.e_suspect()],
    }


def test_intrari_invalide(tmp_path, monkeypatch, capsys):
    procese = tmp_path / "procese.json"
    with pytest.raises(FileNotFoundError):
        procese_din_json(procese)
    for continut, eroare in (("{", ValueError), ("{}", ValueError), ("[{}]", TypeError)):
        procese.write_text(continut, encoding="utf-8")
        with pytest.raises(eroare):
            procese_din_json(procese)
        with pytest.raises(eroare):
            evenimente_din_json(procese)
    procese.write_text("[]", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["inventar", str(tmp_path), "--json"])
    assert main() == 1
    rezultat = capsys.readouterr()
    assert rezultat.out == ""
    assert "Eroare:" in rezultat.err
    assert "evenimente.json" in rezultat.err
