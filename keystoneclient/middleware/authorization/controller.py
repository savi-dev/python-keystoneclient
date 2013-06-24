import functools
import collections
import webob.exc

from keystoneclient.middleware.authorization import engine

register = engine.register

      

def flatten(d, parent_key=''):
    if d == None:
        return {}
    items = []
    for k, v in d.items():
        new_key = parent_key + '.' + k if parent_key else k
        if isinstance(v, collections.MutableMapping):
            items.extend(flatten(v, new_key).items())
        else:
            items.append((new_key, v))
    return dict(items)


def enforce(match_list, target_dict, credentials_dict):
    global _BRAIN
    if not _BRAIN:
        _BRAIN = engine.Brain()
    if not _BRAIN.check(match_list, target_dict, credentials_dict):
        if exc:
            raise exc(*args, **kwargs)
        return False
    return True



def protected(action='None'):
    """Wraps API calls with attribute based access controls (ABAC)."""
    def decorator(f):
       @functools.wraps(f)
       def wrapper(self, request, **kwargs):
           context = request.headers['context']
           method = request.headers['updateBrain']
           method(brain)
           enforce("rule:%s" % action, {}, context)
           return f(self, request, **kwargs)
       return wrapper
    return decorator

def denied_response(req):
        """Deny WSGI Response.

        Returns a standard WSGI response callable with the status of 403 or 401
        depending on whether the REMOTE_USER is set or not.
        """
        if req.remote_user:
            return webob.exc.HTTPForbidden(request=req)
        else:
            return webob.exc.HTTPUnauthorized(request=req)


RESOURCE_ATTRIBUTE_MAP = {}
RESOURCE_HIERARCHY_MAP = {}


