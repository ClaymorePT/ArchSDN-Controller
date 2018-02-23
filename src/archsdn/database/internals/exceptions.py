
class Client_Not_Registered (Exception):
    pass

class Client_Already_Registered (Exception):
    pass

class Datapath_Not_Registered (Exception):
    pass

class Datapath_Already_Registered (Exception):
    pass

class Flow_Already_Registered(Exception):
    pass

class Flow_Not_Registered(Exception):
    pass

class Address_Not_Registered(Exception):
    pass