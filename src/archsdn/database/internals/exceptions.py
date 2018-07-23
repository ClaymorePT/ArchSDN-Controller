
class DatabaseError(Exception):
    def __init__(self, error):
        if isinstance(error, Exception):
            error_str = str(error)
        elif isinstance(error, str):
            error_str = error
        else:
            raise TypeError("error argument type is not supported")
        self.__error_description = error_str if error_str != "" else repr(error)


class ClientNotRegistered(DatabaseError):
    def __str__(self):
        return "Client Not Registered"


class ClientAlreadyRegistered (DatabaseError):
    def __str__(self):
        return "Client Already Registered"


class DatapathNotRegistered (DatabaseError):
    def __str__(self):
        return "Datapath Not Registered"


class DatapathAlreadyRegistered (DatabaseError):
    def __str__(self):
        return "Datapath Already Registered"


class FlowAlreadyRegistered(DatabaseError):
    def __str__(self):
        return "Flow Already Registered"


class FlowNotRegistered(DatabaseError):
    def __str__(self):
        return "Flow Not Registered"


class AddressNotRegistered(DatabaseError):
    def __str__(self):
        return "Address Not Registered"
