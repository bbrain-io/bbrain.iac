from enum import Enum
from dataclasses import MISSING, Field, dataclass, field, fields, is_dataclass
from types import NoneType, UnionType
from typing import Any, Callable, Type, Union, get_args, get_origin


def str_to_bool(s: str):
    if s in ["True", "true"]:
        return True
    elif s in ["False", "false"]:
        return False
    raise ValueError(f"Error converting {s} to bool")


def r(
    func: Callable | None = None,
    parser: Callable | None = None,
    *,
    default=MISSING,
    default_factory=MISSING,
    init=True,
    repr=True,
    hash=None,
    compare=True,
    metadata=None,
    kw_only=MISSING,
) -> Field:
    if func and not callable(func):
        raise ValueError()
    if parser and not callable(parser):
        raise ValueError()

    if (func or parser) and not metadata:
        metadata = {}
    if func:
        metadata["repr"] = func
    if parser:
        metadata["parser"] = parser
    return field(  # type: ignore
        default=default,
        default_factory=default_factory,
        init=init,
        repr=repr,
        hash=hash,
        compare=compare,
        metadata=metadata,
        kw_only=kw_only,
    )


@dataclass
class BaseDataclass:
    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            setattr(
                self,
                field.name,
                self.cast(value, field.type, field.metadata.get("parser")),
            )

    def cast(self, value: Any, _type: Type, parser: Callable = None) -> Any:
        if value is None:
            return None

        # Trying to convert Generic aliases
        origin = get_origin(_type)
        args = list(get_args(_type))

        if origin is list:
            return [self.cast(item, args[0], parser) for item in value]
        if origin is Union or origin is UnionType:
            # Try each type cast until one succeeds, or raise a ValueError
            for _type in args:
                if _type is NoneType:
                    continue

                try:
                    return self.cast(value, _type, parser)
                except Exception:
                    pass
            raise ValueError(
                f"Couldn't cast Union type to types {args}. Value: {value}"
            )
        if origin is dict:
            return {
                self.cast(k, args[0], parser): self.cast(v, args[1], parser)
                for k, v in value.items()
            }

        if isinstance(value, _type):
            return value

        if parser:
            return parser(value)

        if _type is bool:
            return str_to_bool(value)

        # Expand dict as kwargs for dataclasses
        if is_dataclass(_type) and isinstance(value, dict):
            return _type(**value)

        return _type(value)

    def __json__(self):
        data = {}
        for field in fields(self):
            if (value := getattr(self, field.name)) is None:
                continue
            data[field.name] = value
        return data

    def __manifest__(self):
        raise NotImplementedError


class AutoEnum(Enum):
    def _generate_next_value_(name, *_):
        return name

    def __str__(self):
        return self.value

    def __json__(self):
        return self.name
