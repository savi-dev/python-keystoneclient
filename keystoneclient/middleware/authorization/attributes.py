
ATTR_NOT_SPECIFIED = object()
SHARED = 'shared'

def _verify_dict_keys(expected_keys, target_dict, strict=True):
    """ Allows to verify keys in a dictionary.
    :param expected_keys: A list of keys expected to be present.
    :param target_dict: The dictionary which should be verified.
    :param strict: Specifies whether additional keys are allowed to be present.
    :return: True, if keys in the dictionary correspond to the specification.
    """
    if not isinstance(target_dict, dict):
        msg = (_("Invalid input. '%(target_dict)s' must be a dictionary "
                 "with keys: %(expected_keys)s") %
               dict(target_dict=target_dict, expected_keys=expected_keys))
        return msg

    expected_keys = set(expected_keys)
    provided_keys = set(target_dict.keys())

    predicate = expected_keys.__eq__ if strict else expected_keys.issubset

    if not predicate(provided_keys):
        msg = (_("Validation of dictionary's keys failed."
                 "Expected keys: %(expected_keys)s "
                 "Provided keys: %(provided_keys)s") % locals())
        return msg

def is_attr_set(attribute):
    return not (attribute is None or attribute is ATTR_NOT_SPECIFIED)


def _validate_values(data, valid_values=None):
    if data not in valid_values:
        msg = (_("'%(data)s' is not in %(valid_values)s") %
               dict(data=data, valid_values=valid_values))
        LOG.debug(msg)
        return msg


def _validate_string(data, max_len=None):
    if not isinstance(data, basestring):
        msg = _("'%s' is not a valid string") % data
        LOG.debug(msg)
        return msg

    if max_len is not None and len(data) > max_len:
        msg = (_("'%(data)s' exceeds maximum length of %(max_len)s") %
               dict(data=data, max_len=max_len))
        LOG.debug(msg)
        return msg

def _validate_range(data, valid_values=None):
    min_value = valid_values[0]
    max_value = valid_values[1]
    if not min_value <= data <= max_value:
        msg = _("'%(data)s' is not in range %(min_value)s through "
                "%(max_value)s") % dict(data=data,
                                        min_value=min_value,
                                        max_value=max_value)
        LOG.debug(msg)
        return msg


def _validate_no_whitespace(data):
    """Validates that input has no whitespace."""
    if len(data.split()) > 1:
        msg = _("'%s' contains whitespace") % data
        LOG.debug(msg)
        raise q_exc.InvalidInput(error_message=msg)
    return data

def _validate_mac_address(data, valid_values=None):
    try:
        netaddr.EUI(_validate_no_whitespace(data))
    except Exception:
        msg = _("'%s' is not a valid MAC address") % data
        LOG.debug(msg)
        return msg


def _validate_ip_address(data, valid_values=None):
    try:
        netaddr.IPAddress(_validate_no_whitespace(data))
    except Exception:
        msg = _("'%s' is not a valid IP address") % data
        LOG.debug(msg)
        return msg


def _validate_ip_pools(data, valid_values=None):
    """Validate that start and end IP addresses are present

    In addition to this the IP addresses will also be validated

    """
    if not isinstance(data, list):
        msg = _("Invalid data format for IP pool: '%s'") % data
        LOG.debug(msg)
        return msg

    expected_keys = ['start', 'end']
    for ip_pool in data:
        msg = _verify_dict_keys(expected_keys, ip_pool)
        if msg:
            LOG.debug(msg)
            return msg
        for k in expected_keys:
            msg = _validate_ip_address(ip_pool[k])
            if msg:
                LOG.debug(msg)
                return msg

def _validate_uuid(data, valid_values=None):
    if not uuidutils.is_uuid_like(data):
        msg = _("'%s' is not a valid UUID") % data
        LOG.debug(msg)
        return msg


def _validate_uuid_or_none(data, valid_values=None):
    if data is not None:
        return _validate_uuid(data)


def _validate_uuid_list(data, valid_values=None):
    if not isinstance(data, list):
        msg = _("'%s' is not a list") % data
        LOG.debug(msg)
        return msg

    for item in data:
        msg = _validate_uuid(item)
        if msg:
            LOG.debug(msg)
            return msg

    if len(set(data)) != len(data):
        msg = _("Duplicate items in the list: '%s'") % ', '.join(data)
        LOG.debug(msg)
        return msg

def _validate_dict(data, key_specs=None):
    if not isinstance(data, dict):
        msg = _("'%s' is not a dictionary") % data
        LOG.debug(msg)
        return msg

    # Do not perform any further validation, if no constraints are supplied
    if not key_specs:
        return

    # Check whether all required keys are present
    required_keys = [key for key, spec in key_specs.iteritems()
                     if spec.get('required')]

    if required_keys:
        msg = _verify_dict_keys(required_keys, data, False)
        if msg:
            LOG.debug(msg)
            return msg

    # Perform validation of all values according to the specifications.
    for key, key_validator in [(k, v) for k, v in key_specs.iteritems()
                               if k in data]:

        for val_name in [n for n in key_validator.iterkeys()
                         if n.startswith('type:')]:
            # Check whether specified validator exists.
            if val_name not in validators:
                msg = _("Validator '%s' does not exist.") % val_name
                LOG.debug(msg)
                return msg

            val_func = validators[val_name]
            val_params = key_validator[val_name]

            msg = val_func(data.get(key), val_params)
            if msg:
                LOG.debug(msg)
                return msg


def _validate_dict_or_none(data, key_specs=None):
    if data is not None:
        return _validate_dict(data, key_specs)

def _validate_dict_or_empty(data, key_specs=None):
    if data != {}:
        return _validate_dict(data, key_specs)


def _validate_non_negative(data, valid_values=None):
    try:
        data = int(data)
    except (ValueError, TypeError):
        msg = _("'%s' is not an integer") % data
        LOG.debug(msg)
        return msg

    if data < 0:
        msg = _("'%s' should be non-negative") % data
        LOG.debug(msg)
        return msg


def convert_to_boolean(data):
    if isinstance(data, basestring):
        val = data.lower()
        if val == "true" or val == "1":
            return True
        if val == "false" or val == "0":
            return False
    elif isinstance(data, bool):
        return data
    elif isinstance(data, int):
        if data == 0:
            return False
        elif data == 1:
            return True
    msg = _("'%s' cannot be converted to boolean") % data
    raise q_exc.InvalidInput(error_message=msg)


def convert_to_int(data):
    try:
        return int(data)
    except (ValueError, TypeError):
        msg = _("'%s' is not a integer") % data
        raise q_exc.InvalidInput(error_message=msg)


def convert_kvp_str_to_list(data):
    """Convert a value of the form 'key=value' to ['key', 'value'].

    :raises: q_exc.InvalidInput if any of the strings are malformed
                                (e.g. do not contain a key).
    """
    kvp = [x.strip() for x in data.split('=', 1)]
    if len(kvp) == 2 and kvp[0]:
        return kvp
    msg = _("'%s' is not of the form <key>=[value]") % data
    raise q_exc.InvalidInput(error_message=msg)


def convert_kvp_list_to_dict(kvp_list):
    """Convert a list of 'key=value' strings to a dict.

    :raises: q_exc.InvalidInput if any of the strings are malformed
                                (e.g. do not contain a key) or if any
                                of the keys appear more than once.
    """
    if kvp_list == ['True']:
        # No values were provided (i.e. '--flag-name')
        return {}
    kvp_map = {}
    for kvp_str in kvp_list:
        key, value = convert_kvp_str_to_list(kvp_str)
        kvp_map.setdefault(key, set())
        kvp_map[key].add(value)
    return dict((x, list(y)) for x, y in kvp_map.iteritems())


def convert_none_to_empty_list(value):
    return [] if value is None else value


def convert_none_to_empty_dict(value):
    return {} if value is None else value


def convert_to_list(data):
    if data is None:
        return []
    elif hasattr(data, '__iter__'):
        return list(data)
    else:
        return [data]

validators = {'type:dict': _validate_dict,
              'type:dict_or_none': _validate_dict_or_none,
              'type:dict_or_empty': _validate_dict_or_empty,
              'type:ip_pools': _validate_ip_pools,
              'type:non_negative': _validate_non_negative,
              'type:regex': _validate_regex,
              'type:string': _validate_string,
              'type:subnet': _validate_subnet,
              'type:uuid': _validate_uuid,
              'type:uuid_or_none': _validate_uuid_or_none,
              'type:uuid_list': _validate_uuid_list,
              'type:values': _validate_values}
