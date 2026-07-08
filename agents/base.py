from abc import ABC, abstractmethod


class BaseAgent(ABC):
    name: str

    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    def run(self) -> None:
        """Run the agent."""

