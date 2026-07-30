from __future__ import annotations

import inspect
from functools import wraps
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from ppf.ho_01 import binding_domain_difference, forwarding_trace, transparent_wrapper


def ordinary(a: int, /, b: str = "b", *args: object, flag: bool, **kwargs: object) -> tuple:
    return a, b, args, flag, kwargs


def test_transparent_wrapper_preserves_stacked_signature_and_forwarding() -> None:
    wrapped = transparent_wrapper(transparent_wrapper(ordinary))
    assert inspect.signature(wrapped) == inspect.signature(ordinary)
    result, trace = forwarding_trace(ordinary, 1, "x", 3, flag=True, extra=4)
    assert result == (1, "x", (3,), True, {"extra": 4})
    assert trace == ((1, "x", 3), {"flag": True, "extra": 4})


@settings(max_examples=50, derandomize=True, database=None)
@given(
    st.lists(st.integers(), max_size=4),
    st.dictionaries(st.sampled_from(["b", "flag", "extra"]), st.integers(), max_size=3),
)
def test_binding_domains_are_equivalent(
    arguments: list[int],
    keywords: dict[str, int],
) -> None:
    wrapped = transparent_wrapper(ordinary)
    assert binding_domain_difference(
        ordinary,
        wrapped,
        [(tuple(arguments), keywords)],
    ) is None


def test_broken_wrapper_produces_a_replayable_boundary_counterexample() -> None:
    def broken(function: Any) -> Any:
        @wraps(function)
        def wrapper(value: int) -> Any:
            return function(value, flag=False)

        wrapper.__signature__ = inspect.Signature(
            [inspect.Parameter("value", inspect.Parameter.POSITIONAL_OR_KEYWORD)]
        )
        return wrapper

    counterexample = binding_domain_difference(
        ordinary,
        broken(ordinary),
        [((1,), {"flag": True}), ((1, "b"), {"flag": True})],
    )
    assert counterexample == ((1,), {"flag": True})
