"""HO-01 transparent callable signature propagation probes."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Iterable
from functools import wraps
from typing import Any


def transparent_wrapper[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    """Forward calls while preserving runtime and static callable identity."""

    @wraps(function)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        return function(*args, **kwargs)

    return wrapped


def binding_domain_difference(
    original: Callable[..., Any],
    wrapped: Callable[..., Any],
    samples: Iterable[tuple[tuple[Any, ...], dict[str, Any]]],
) -> tuple[tuple[Any, ...], dict[str, Any]] | None:
    """Return the first sample accepted by exactly one signature."""
    original_signature = inspect.signature(original)
    wrapped_signature = inspect.signature(wrapped)
    for args, kwargs in samples:
        accepted: list[bool] = []
        for signature in (original_signature, wrapped_signature):
            try:
                signature.bind(*args, **kwargs)
            except TypeError:
                accepted.append(False)
            else:
                accepted.append(True)
        if accepted[0] != accepted[1]:
            return args, kwargs
    return None


def forwarding_trace[**P, R](
    function: Callable[P, R],
    *args: P.args,
    **kwargs: P.kwargs,
) -> tuple[R, tuple[tuple[Any, ...], dict[str, Any]]]:
    """Observe the exact arguments received by a wrapped delegate."""
    trace: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    @wraps(function)
    def observed(*inner_args: P.args, **inner_kwargs: P.kwargs) -> R:
        trace.append((inner_args, inner_kwargs))
        return function(*inner_args, **inner_kwargs)

    result = transparent_wrapper(observed)(*args, **kwargs)
    return result, trace[0]
