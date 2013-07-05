import functools
import collections
import logging
import webob.exc

from keystoneclient.middleware.authorization import engine

register = engine.register

LOG=logging.getLogger(__name__)

_BRAIN=None

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
           LOG.debug(_('ABAC: Authorizing %s(%s)') % (
               action,
                ', '.join(['%s=%s' % (k, kwargs[k]) for k in kwargs])))
           context = request.headers['context']
           method = request.headers['updateBrain']
           policy=method()
           global _BRAIN
           if not _BRAIN:
              _BRAIN=engine.Brain()
           _BRAIN=_BRAIN.load_json(policy) 
           LOG.debug("Brain Policy %s" % _BRAIN.rules)
           match_list = ("rule:%s" % action,)
           if not _BRAIN.check(match_list, {}, context):
              return webob.exc.HTTPUnauthorized(request=request)
           return f(self, request, **kwargs)
       return wrapper
    return decorator


RESOURCE_ATTRIBUTE_MAP = {}
RESOURCE_HIERARCHY_MAP = {}


