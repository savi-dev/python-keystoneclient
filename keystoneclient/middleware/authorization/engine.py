'''
Created on Jun 10, 2013

@author: mfaraji<ms.faraji@utoronto.ca>
'''
"""Common Policy Engine Implementation"""

import logging

from keystoneclient.openstack.common import jsonutils
LOG= logging.getLogger(__name__)


_BRAIN = None


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
    def load_json(cls, data, default_rule=None, logger=None):
        """Init a brain using json instead of a rules dictionary."""
        rules_dict = jsonutils.loads(data)
        return cls(rules=rules_dict, default_rule=default_rule, logger=logger)

    def __init__(self, rules=None, default_rule=None, logger=None):
        self.rules = rules or {}
        self.default_rule = default_rule
        LOG = logger

    def add_rule(self, key, match):
        self.rules[key] = match

    def _check(self, match, target_dict, cred_dict):
        
        match_kind, match_value = match.split(':', 1)
        try:
            f = getattr(self, '_check_%s' % match_kind)
        except AttributeError:
            if not self._check_generic(match, target_dict, cred_dict):
                return False
        else:
            if not f(match_value, target_dict, cred_dict):
                return False
        return True

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
def _check_rule(match, target_dict, cred_dict):
   """Recursively checks credentials based on the brains rules."""
   try:
       new_match_list = self.rules[match]
   except KeyError:
       if brain.default_rule and match != brain.default_rule:
          new_match_list = ('rule:%s' % brain.default_rule,)
       else:
          return False          

   return self.check(new_match_list, target_dict, cred_dict)

@register('role')
def _check_role(self, match, target_dict, cred_dict):
    """Check that there is a matching role in the cred dict."""
    LOG.debug("Role %s" % match)
    return match.lower() in [x.lower() for x in cred_dict['roles']]

@register('tenant')
def _check_tenant(self, match, taget_dict, cred_dict):
    LOG.debug("Tenant %s" % match)
    return match.lower() in [x.lower() for x in cred_dict['tenant']]


@register(None)
def _check_generic(brain, match_kind, match, target_dict, cred_dict):
    match = match % target_dict
    if match_kind in cred_dict:
        return match == unicode(cred_dict[match_kind])
    return False



