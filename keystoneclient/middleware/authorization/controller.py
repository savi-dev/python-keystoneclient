import functools
import collections
import logging
import webob.exc


from oslo.config import cfg
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

def _is_attribute_explicitly_set(attribute_name, resource, target):
    """Verify that an attribute is present and has a non-default value"""
    return ('default' in resource[attribute_name] and
            attribute_name in target and
            target[attribute_name] is not attributes.ATTR_NOT_SPECIFIED and
            target[attribute_name] != resource[attribute_name]['default'])

def _build_target(action, original_target, context):
    """Augment dictionary of target attributes for policy engine.

    This routine adds to the dictionary attributes belonging to the
    "parent" resource of the targeted one.
    """
    target = original_target.copy()
    resource, _a = get_resource_and_action(action)
    hierarchy_info = attributes.RESOURCE_HIERARCHY_MAP.get(resource, None)
    if hierarchy_info and plugin:
        # use the 'singular' version of the resource name
        parent_resource = hierarchy_info['parent'][:-1]
        parent_id = hierarchy_info['identified_by']
        f = getattr(plugin, 'get_%s' % parent_resource)
        # f *must* exist, if not found it is better to let quantum explode
        # Note: we do not use admin context
        data = f(context, target[parent_id], fields=['tenant_id'])
        target['%s_tenant_id' % parent_resource] = data['tenant_id']
    return target

def _build_match_rule(action, target):
    """Create the rule to match for a given action.

    The policy rule to be matched is built in the following way:
    1) add entries for matching permission on objects
    2) add an entry for the specific action (e.g.: create_network)
    3) add an entry for attributes of a resource for which the action
       is being executed (e.g.: create_network:shared)

    """

    match_rule = policy.RuleCheck('rule', action)
    resource, is_write = get_resource_and_action(action)
    if is_write:
        # assigning to variable with short name for improving readability
        res_map = attributes.RESOURCE_ATTRIBUTE_MAP
        if resource in res_map:
            for attribute_name in res_map[resource]:
                if _is_attribute_explicitly_set(attribute_name,
                                                res_map[resource],
                                                target):
                    attribute = res_map[resource][attribute_name]
                    if 'enforce_policy' in attribute and is_write:
                        attr_rule = policy.RuleCheck('rule', '%s:%s' %
                                                     (action, attribute_name))
                        match_rule = policy.AndCheck([match_rule, attr_rule])

    return match_rule



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


