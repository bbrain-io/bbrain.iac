from abc import ABC, abstractmethod

from bbrain.iac.ovh.client import Client


class BaseManifest(ABC):
    @abstractmethod
    async def apply(self, client: Client):
        ...
