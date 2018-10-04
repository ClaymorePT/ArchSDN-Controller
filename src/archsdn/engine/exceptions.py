class EngineException(Exception):
    def __repr__(self):
        return "<{:s} type> object at address 0x{:x}".format(type(self).__name__, id(self))


class SectorException(EngineException):
    def __str__(self):
        return "Sector Exception"


class EntityException(EngineException):
    def __str__(self):
        return "Entity Exception"


class NetworkException(EngineException):
    def __str__(self):
        return "Network Exception"


class SectorGenericException(SectorException):
    def __init__(self, reason):
        self.__reason = reason

    def __str__(self):
        return "SectorGenericException: {:s}".format(self.__reason)


class EntityAlreadyRegistered(SectorException):
    def __str__(self):
        return "Entity Already Registered"


class EntityNotRegistered(SectorException):
    def __str__(self):
        return "Entity Not Registered"


class LinkException(SectorException):
    def __init__(self, reason):
        self.__reason = reason

    def __str__(self):
        return self.__reason


class EntitiesAlreadyConnected(SectorException):
    def __str__(self):
        return "Entities Already Connected"


class EntitiesNotConnected(SectorException):
    def __str__(self):
        return "Entities Not Connected"


class PortNotUsed(SectorException):
    def __str__(self):
        return "Port Not Used"


class UnexpectedConnectedEntity(SectorException):
    def __init__(self, reason):
        self.__reason = reason

    def __str__(self):
        return self.__reason


class SwitchException(EntityException):
    def __str__(self):
        return "Switch Exception"


class PortAlreadyRegistered(SwitchException):
    def __str__(self):
        return "Port Already Registered"


class PortNotRegistered(SwitchException):
    def __str__(self):
        return "Port Not Registered"


class SwitchPortAlreadyConnected(LinkException):
    def __init__(self, port_no):
        self.__port_no = port_no

    def __str__(self):
        return "Switch port {:d} already used.".format(self.__port_no)


class PathNotFound(SectorException):
    def __init__(self, reason=None):
        self.__reason = reason

    def __str__(self):
        return self.__reason if self.__reason else "Path Not found"


class CannotCreateScenario(SectorException):
    def __str__(self):
        return "Cannot Create Scenario"
