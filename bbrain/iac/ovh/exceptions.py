from aiohttp.client_exceptions import ClientResponseError

# 400
class HTTPBadRequest(ClientResponseError):
    pass


# 401
class HTTPUnauthorized(ClientResponseError):
    pass


# 403
class HTTPForbidden(ClientResponseError):
    pass


# 404
class HTTPNotFound(ClientResponseError):
    pass


# 405
class HTTPMethodNotAllowed(ClientResponseError):
    pass


# 409
class HTTPConflict(ClientResponseError):
    pass


class InvalidRegion(Exception):
    """Raised when region is not in `REGIONS`."""


class UnknownManifest(Exception):
    """Exception raised when a manifest is unknown"""
