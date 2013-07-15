'''
Created on Jun 10, 2013

@author: mfaraji<ms.faraji@utoronto.ca>
'''
"""Common Policy Engine Implementation"""
import abc
import logging

from keystoneclient.openstack.common import jsonutils
LOG= logging.getLogger(__name__)



def set_brain(brain):
    """Set the brain used by enforce().

    Defaults use Brain() if not set.

    """
    global _BRAIN
    _BRAIN = brain


def reset():
    """Clear the brain used by enforce()."""
    global _BRAIN
    _BRAIN = None


class Brain(object):
    """Implements policy checking."""

    _checks = {}

    @classmethod
    def _register(cls, name, func):
        cls._checks[name] = func

    @classmethod
    def load_json(cls, data, default_rule=None):
        """Init a brain using json instead of a rules dictionary."""
        rules_dict = jsonutils.loads(data)
        return cls(rules=rules_dict, default_rule=default_rule)

    def __init__(self, rules=None, default_rule=None):
        self.rules = rules or {}
        self.default_rule = default_rule
        LOG.debug("RRRRRRRRRRRRRRRRRRRR %s" % rules)
        

    def add_rule(self, key, match):
        self.rules[key] = match

    def _check(self, match, target_dict, cred_dict): 
        try:
            match_kind, match_value = match.split(':', 1)
        except Exception:
            LOG.exception(_("Failed to understand rule %(match)r") % locals())
            # If the rule is invalid, fail closed
            return False

        func = None
        try:
            old_func = getattr(self, '_check_%s' % match_kind)
        except AttributeError:
            func = self._checks.get(match_kind, self._checks.get(None, None))
        else:
            LOG.warning(_("Inheritance-based rules are deprecated; update "
                          "_check_%s") % match_kind)
            func = (lambda brain, kind, value, target, cred:
                        old_func(value, target, cred))

        if not func:
            LOG.error(_("No handler for matches of kind %s") % match_kind)
            # Fail closed
            return False

        return func(self, match_kind, match_value, target_dict, cred_dict)

    def check(self, match_list, target_dict, cred_dict):
        """Checks authorization of some rules against credentials.

        Detailed description of the check with examples in policy.enforce().

        :param match_list: nested tuples of data to match against
        :param target_dict: dict of object properties
        :param credentials_dict: dict of actor properties

        :returns: True if the check passes

        """
        LOG.debug("Match %s" % match_list)
        if not match_list:
            return True
        for and_list in match_list:
            LOG.debug('and_list %s' % and_list)
            if isinstance(and_list, basestring):
                and_list = (and_list,)
            if all([self._check(item, target_dict, cred_dict)
                    for item in and_list]):
                return True
        return False


class BaseCheck(object):
    """
    Abstract base class for Check classes.
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __str__(self):
        pass

    @abc.abstractmethod
    def __call__(self, target, cred):

        pass

class FalseCheck(BaseCheck):
    """
    A policy check that always returns False (disallow).
    """

    def __str__(self):
        return "!"

    def __call__(self, target, cred):
        return False

class TrueCheck(BaseCheck):
    """
    A policy check that always returns True (allow).
    """

    def __str__(self):
        return "@"

    def __call__(self, target, cred):
        return True


def register(name, func=None):
    """
    Register a function as a policy check.

    """
    def decorator(func):
        # Register the function
        Brain._register(name, func)
        return func
    # If the function is given, do the registration
    if func:
        return decorator(func)
    return decorator

@register('rule')
def _check_rule(brain, match_kind, match, target_dict, cred_dict):
   """Recursively checks credentials based on the brains rules."""
   try:
       new_match_list = brain.rules[match]
   except KeyError:
       if brain.default_rule and match != brain.default_rule:
          new_match_list = ('rule:%s' % brain.default_rule,)
       else:
          return False          

   return brain.check(new_match_list, target_dict, cred_dict)

@register('role')
def _check_role(brain, match_kind, match, target_dict, context):
    """Check that there is a matching role in the cred dict."""
    LOG.debug("Role %s" % match)
    return match.lower() in [x.lower() for x in context.roles]

@register('tenant_id')
def _check_tenant_id(brain, match_kind, match, taget_dict, context):
    LOG.debug("Checking Tenant Id%s" % match)
    return match.lower() == context.tenant_id.lower()

@register('tenant')
def _check_tenant_id(brain, match_kind, match, taget_dict, context):
    LOG.debug("Checking Tenant Name %s" % match)
    result= match.lower() == context.tenant.lower()
    return result


@register('domain')
def _check_domain(brain, match_kind, match, target_dict, context):
   LOG.debug("Domain %s" % match)
   return match.lower() == context.tenant_id.lower()

@register(None)
def _check_generic(brain, match_kind, match, target_dict, context):
    cred_dict = context.to_dict()
    match = match % target_dict
    if match_kind in cred_dict:
        return match == unicode(cred_dict[match_kind])
    return False

@register('field')
class FieldCheck(policy.Check):
    def __init__(self, kind, match):
        # Process the match
        resource, field_value = match.split(':', 1)
        field, value = field_value.split('=', 1)

        super(FieldCheck, self).__init__(kind, '%s:%s:%s' %
                                         (resource, field, value))

        # Value might need conversion - we need help from the attribute map
        try:
            attr = attributes.RESOURCE_ATTRIBUTE_MAP[resource][field]
            conv_func = attr['convert_to']
        except KeyError:
            conv_func = lambda x: x

        self.field = field
        self.value = conv_func(value)

    def __call__(self, target_dict, cred_dict):
        target_value = target_dict.get(self.field)
        # target_value might be a boolean, explicitly compare with None
        if target_value is None:
            LOG.debug(_("Unable to find requested field: %(field)s in "
                        "target: %(target_dict)s"),
                      {'field': self.field,
                       'target_dict': target_dict})
            return False

        return target_value == self.value

