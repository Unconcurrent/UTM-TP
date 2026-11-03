from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Final, Literal, Never, cast

type _State[T] = tuple[Literal[True], T] | tuple[Literal[False], Exception]


class Result[T]:
    """Rezultat cu valoare sau eroare."""

    def __init__(self, state: _State[T]):
        self.state: Final[_State[T]] = state

    @property
    def is_ok(self) -> bool:
        return self.state[0]

    @property
    def value(self) -> T | Exception:
        return self.state[1]

    def unwrap(self) -> T:
        state = self.state
        if state[0] is False:
            raise state[1]
        return state[1]

    def then[U](self, callback: Callable[[T], U | Result[U]]) -> Result[U]:
        state = self.state
        if state[0] is False:
            return err(state[1])
        try:
            result = callback(state[1])
            if isinstance(result, Result):
                return cast(Result[U], result)
            return ok(cast(U, result))
        except Exception as ex:
            return err(ex)

    def then_each[V, U](
        self: Result[Iterable[V]], callback: Callable[[V], U | Result[U]]
    ) -> Result[list[U]]:
        return self.then(
            lambda values: Result.sequence(ok(value).then(callback) for value in values)
        )

    @staticmethod
    def sequence[U](results: Iterable[Result[U]]) -> Result[list[U]]:
        try:
            values: list[U] = []
            for result in results:
                state = result.state
                if state[0] is False:
                    return err(state[1])
                values.append(state[1])
            return ok(values)
        except Exception as e:
            return err(e)

    def catch[U](self, callback: Callable[[Exception], U | Result[U]]) -> Result[T | U]:
        state = self.state
        return self if state[0] is True else ok(state[1]).then(callback)

    def match[U, V](self, ok_func: Callable[[T], U], err_func: Callable[[Exception], V]) -> U | V:
        state = self.state
        return ok_func(state[1]) if state[0] is True else err_func(state[1])


def ok[T](r: T) -> Result[T]:
    return Result((True, r))


def err(e: Exception) -> Result[Never]:
    return Result((False, e))

def wrap[T, **P](func: Callable[P, T]) -> Callable[P, Result[T]]:
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> Result[T]:
        try:
            return ok(func(*args, **kwargs))
        except Exception as error:
            return err(error)

    return wrapped
