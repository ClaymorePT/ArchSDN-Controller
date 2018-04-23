from abc import ABC, abstractmethod
from threading import Lock


class Service(ABC):

    @property
    def id(self):
        return id(self)

    @abstractmethod
    def has_entity(self, entity_id):
        pass


