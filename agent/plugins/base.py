from abc import ABC, abstractmethod

from ..models import Finding


class VulnPlugin(ABC):
    name: str

    @abstractmethod
    async def run(self, context: dict) -> list[Finding]:
        raise NotImplementedError
