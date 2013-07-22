import functools
import collections
import logging
import webob.exc


from oslo.config import cfg
from keystoneclient.middleware.authorization import engine

register = engine.register

LOG=logging.getLogger(__name__)

_BRAIN=None


def init(updateMethod):
    policy=updateMethod()
    global _BRAIN
    if not _BRAIN:
       _BRAIN=engine.Brain()
    _BRAIN=_BRAIN.load_json(policy)
    LOG.debug("Brain Policy %s" % _BRAIN.rules)


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

def _is_attribute_explicitly_set(attribute_name, resource, target):
    """Verify that an attribute is present and has a non-default value"""
    return ('default' in resource[attribute_name] and
            attribute_name in target and
            target[attribute_name] is not attributes.ATTR_NOT_SPECIFIED and
            target[attribute_name] != resource[attribute_name]['default'])

def _build_target(action, original_target, context):
   pass

def _build_match_rule(action, target):
   pass

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
           init(method)
           match_list = ("rule:%s" % action,)
           if not _BRAIN.check(match_list, {}, context):
              return webob.exc.HTTPUnauthorized(request=request)
           return f(self, request, **kwargs)
       return wrapper
    return decorator


class filter:
    def __init__(self, context, action):
        self.credentials = context.to_dict()
        self.match_rule = ("rule:%s" % action,)

    def __call__(self, obj):
        return _BRAIN.check(self.match_rule, obj, self.credentials)

def filterprotected(action):
    """Wraps filtered API calls with  Attribute Based access controls (ABAC)."""

    def _filterprotected(f):
        @functools.wraps(f)
        def wrapper(self, request, **kwargs):
            filters = None
            if not context['is_admin']:
                context = request.headers['context']
                method = request.headers['updateBrain']
                init(method)
                LOG.debug(_('ABAC: Creating Filter'))
                _filter = filter(context, action)
            else:
                LOG.warning(_('ABAC: Bypassing authorization'))
            return f(self, request, _filter, **kwargs)
        return wrapper
    return _filterprotected

RESOURCE_ATTRIBUTE_MAP = {}
RESOURCE_HIERARCHY_MAP = {}


