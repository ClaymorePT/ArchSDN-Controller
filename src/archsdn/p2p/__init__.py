'''

This module implements the P2P communication server.
Peers communicate by sending messages from one to another.
These messages carry requests.

Requests that require information which may not be ready-available, should respond with a request ticket.
This ticket contains a request identification. The request answer will be later sent.

It is the responsibility of the peer which performs the request, to deal with the asynchronous nature of the requests.
A peer must wait for a message indicating the success or failure to complete a request, to react accordingly.

Requests are structured as tuples:
(peer ID, Request name, data_dict{})

Replies are structured as tuples:
(Reply name, result structure)

'''

__all__ = [
    "get_controller_proxy",
    "initialize_server",
    "shutdown_server",
    "ConnectionFailed",
    "UnexpectedResponse"
]

from archsdn.p2p.peer_proxy import get_controller_proxy
from archsdn.p2p.server import initialize_server, shutdown_server
from archsdn.p2p.exceptions import ConnectionFailed, UnexpectedResponse
