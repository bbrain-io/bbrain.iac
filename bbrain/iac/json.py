from datetime import datetime
import json
from typing import Any
from pygments import highlight
from ipaddress import IPv4Address, IPv4Network
from pygments.lexers.data import JsonLexer
from pygments.formatters.terminal256 import Terminal256Formatter


class CustomEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        str_types = (IPv4Address, datetime)

        if hasattr(o, "__json__"):
            return o.__json__()
        elif isinstance(o, str_types):
            return str(o)
        elif isinstance(o, IPv4Address | IPv4Network):
            return str(o)
        elif isinstance(o, datetime):
            return datetime.isoformat(o)

        return super().default(o)


def dumps(
    obj,
    *,
    skipkeys=False,
    ensure_ascii=True,
    check_circular=True,
    allow_nan=True,
    cls=CustomEncoder,
    indent=None,
    separators=None,
    default=None,
    sort_keys=False,
    **kw
):
    return json.dumps(
        obj,
        skipkeys=skipkeys,
        ensure_ascii=ensure_ascii,
        check_circular=check_circular,
        allow_nan=allow_nan,
        cls=cls,
        indent=indent,
        separators=separators,
        default=default,
        sort_keys=sort_keys,
        **kw
    )


def jsond(o):
    data = json.dumps(o, indent=4, cls=CustomEncoder)
    print(highlight(data, JsonLexer(), Terminal256Formatter()))
