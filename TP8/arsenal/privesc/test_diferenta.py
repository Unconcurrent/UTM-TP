from .diferenta import diferenta


def test_doar_ce_e_nou() -> None:
    acum = {"a", "b", "c"}
    baza = {"a", "b"}
    assert diferenta(acum, baza) == {"c"}
    assert diferenta(acum, baza | {"vechi"}) == {"c"}
