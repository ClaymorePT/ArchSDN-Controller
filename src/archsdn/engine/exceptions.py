

class SectorException(Exception):

    def __repr__(self):
        return "<{:s} type> object at address 0x{:x}".format(type(self).__name__, id(self))


class EntityException(Exception):

    def __repr__(self):
        return "<{:s} type> object at address 0x{:x}".format(type(self).__name__, id(self))


class SectorGenericException(Exception):
    def __init__(self, reason):
        self.__reason = reason

    def __str__(self):
        return "SectorGenericException: {:s}".format(self.__reason)


class EntityAlreadyRegistered(SectorException):
    pass


class EntityNotRegistered(SectorException):
    pass


class SwitchException(EntityException):
    pass


class PortAlreadyRegistered(SwitchException):
    pass

class PortNotRegistered(SwitchException):
    pass