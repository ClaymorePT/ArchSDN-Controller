
class ConnectionFailed(Exception):
    def __str__(self):
        return "Connection Failed"


class UnexpectedResponse(Exception):
    def __init__(self, response):
        self.response = response

    def __str__(self):
        return "Unexpected Response: {:s}".format(str(self.response))

