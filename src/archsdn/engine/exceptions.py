class EngineException(Exception):
    def __repr__(self):
        return "<{:s} type> object at address 0x{:x}".format(type(self).__name__, id(self))


class SectorException(EngineException):
    pass


class EntityException(EngineException):
    pass


class NetworkException(EngineException):
    pass


class SectorGenericException(SectorException):
    def __init__(self, reason):
        self.__reason = reason

    def __str__(self):
        return "SectorGenericException: {:s}".format(self.__reason)


class EntityAlreadyRegistered(SectorException):
    pass


class EntityNotRegistered(SectorException):
    pass


class LinkException(SectorException):
    def __init__(self, reason):
        self.__reason = reason

    def __str__(self):
        return self.__reason


class EntitiesAlreadyConnected(SectorException):
    pass


class EntitiesNotConnected(SectorException):
    pass


class PortNotUsed(SectorException):
    pass


class UnexpectedConnectedEntity(SectorException):
    def __init__(self, reason):
        self.__reason = reason

    def __str__(self):
        return self.__reason


class SwitchException(EntityException):
    pass


class PortAlreadyRegistered(SwitchException):
    pass


class PortNotRegistered(SwitchException):
    pass


class SwitchPortAlreadyConnected(LinkException):
    def __init__(self, port_no):
        self.__port_no = port_no

    def __str__(self):
        return "Switch port {:d} already used.".format(self.__port_no)


class PathNotFound(SectorException):
    pass


class CannotCreateScenario(SectorException):
    pass
