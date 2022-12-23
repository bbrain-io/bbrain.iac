from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bbrain.iac.ovh.client import Client


class BaseManifest(ABC):
    @abstractmethod
    async def apply(self, client: Client, *args, **kwargs):
        ...
