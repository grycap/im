from functools import wraps
from IM.awm.authorization import authenticate
from flask import Response, request
from IM.awm.models.error import Error


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            # try to call authenticate similarly to FastAPI dependency
            user_info = authenticate(request)
        except Exception as e:
            # convert auth failure to JSON error response
            err = Error(id="401", description=str(e) if str(e) else "Permission denied")
            return Response(err.model_dump_json(exclude_unset=True), status=401,
                            mimetype="application/json")
        kwargs["user_info"] = user_info
        return f(*args, **kwargs)
    return wrapper
