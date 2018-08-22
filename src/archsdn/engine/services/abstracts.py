from abc import ABC, abstractmethod

class Service(ABC):

    @property
    def id(self):
        return id(self)

    @abstractmethod
    def has_entity(self, entity_id):
        pass

    @abstractmethod
    def has_flow(self, cookie_id):
        pass


