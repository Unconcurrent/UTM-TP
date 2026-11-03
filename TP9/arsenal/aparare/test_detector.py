from collections import Counter
from datetime import UTC, datetime, timedelta

import pytest

from .detector import pe_ip_fereastra, suspecti
from .parse_auth import Esec, esec, pe_ip, primele


def test_pragul_taie() -> None:
    assert esec("Failed password for root from 203.0.113.9 port 51230 ssh2") == ("root", "203.0.113.9")
    assert esec("linie stricata") is None
    date = [Esec(user="root", ip="a") for _ in range(13)] + [Esec(user="ana", ip="b") for _ in range(2)]
    counts = pe_ip(date)
    assert counts == Counter({"a": 13, "b": 2})
    assert suspecti(counts) == [("a", 13)]
    assert suspecti(counts, 2) == [("a", 13), ("b", 2)]
    assert primele(counts, 1) == [("a", 13)]

    baza = datetime(2026, 1, 10, tzinfo=UTC)
    evenimente = [(baza + timedelta(seconds=s), "a") for s in (100, 0, 10, 20)]
    assert pe_ip_fereastra(evenimente, 10) == Counter({"a": 2})


def test_prag_invalid() -> None:
    with pytest.raises(ValueError, match="prag invalid"):
        suspecti({}, 0)
    with pytest.raises(ValueError, match="fereastra invalida"):
        pe_ip_fereastra([], 0)
    with pytest.raises(ValueError, match="top invalid"):
        primele(Counter(), 0)
