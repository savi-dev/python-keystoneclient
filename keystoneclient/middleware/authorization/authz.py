# vim: tabstop=4 shiftwidth=4 softtabstop=4

import httplib
import logging
import os
import stat
import time
import webob.exc

from keystoneclient.middleware.authorization import engine,context
from keystoneclient.openstack.common import jsonutils


CONF = None
for app in 'nova', 'glance', 'quantum', 'cinder', 'janus', 'whale', 'swift':
    try:
        cfg = __import__('%s.openstack.common.cfg' % app,
                         fromlist=['%s.openstack.common' % app])
        # test which application middleware is running in
        if hasattr(cfg, 'CONF') and 'config_file' in cfg.CONF:
            CONF = cfg.CONF
            break
    except ImportError:
        pass
if not CONF:
    from oslo.config import cfg
    CONF = cfg.CONF

LIST_OF_VERSIONS_TO_ATTEMPT = ['v2.0', 'v3.0']

opts = [
    cfg.StrOpt('auth_admin_prefix', default=''),
    cfg.StrOpt('auth_host', default='127.0.0.1'),
    cfg.IntOpt('auth_port', default=35357),
    cfg.StrOpt('auth_protocol', default='https'),
    cfg.StrOpt('auth_uri', default=None),
    cfg.StrOpt('admin_token'),
    cfg.StrOpt('admin_user'),
    cfg.StrOpt('admin_password'),
    cfg.StrOpt('admin_tenant_name', default='admin'),
    cfg.StrOpt('stub_mode', default=False),
    cfg.ListOpt('memcached_servers', deprecated_name='memcache_servers'),
    cfg.StrOpt('memcache_security_strategy', default=None),
    cfg.StrOpt('memcache_secret_key', default=None, secret=True),
    cfg.IntOpt('policy_cache_time', default=300)
]
CONF.register_opts(opts, group='keystone_policy')

CACHE_KEY_TEMPLATE = 'policies'

class InvalidPolicy(Exception):
    pass

class ServiceError(Exception):
    pass


class ConfigurationError(Exception):
    pass


class Authorize(object):
    """Auth Middleware that handles authorizing client calls."""

    def __init__(self, app, conf):
        self.conf = conf
        self.app = app
        self.current_policy=None
        self.logger = logging.getLogger(conf.get('log_name', __name__))
        # where to find the auth service (we use this to validate tokens)
        self.auth_host = self._conf_get('auth_host')
        self.auth_port = int(self._conf_get('auth_port'))
        self.auth_protocol = self._conf_get('auth_protocol')
        self.service = self._conf_get('service')
        if self.auth_protocol == 'http':
            self.http_client_class = httplib.HTTPConnection
        else:
            self.http_client_class = httplib.HTTPSConnection
        self.auth_admin_prefix = self._conf_get('auth_admin_prefix')
        self.auth_uri = self._conf_get('auth_uri')
        if self.auth_uri is None:
            self.auth_uri = '%s://%s:%s' % (self.auth_protocol,
                                            self.auth_host,
                                            self.auth_port)
        # memcache
        self._cache = None
        self._cache_initialized = False
        # memcache value treatment, ENCRYPT or MAC
        self._memcache_security_strategy = \
            self._conf_get('memcache_security_strategy')
        if self._memcache_security_strategy is not None:
            self._memcache_security_strategy = \
                self._memcache_security_strategy.upper()
        self._memcache_secret_key = \
            self._conf_get('memcache_secret_key')
        self.policy_cache_time = int(self._conf_get('policy_cache_time'))

        # Credentials used to verify this component with the Auth service since
        # validating tokens is a privileged call
        self.admin_token = self._conf_get('admin_token')
        self.admin_user = self._conf_get('admin_user')
        self.admin_password = self._conf_get('admin_password')
        self.admin_tenant_name = self._conf_get('admin_tenant_name')


    def _init_cache(self, env):
        cache = self._conf_get('cache')
        memcache_servers = self._conf_get('memcached_servers')

        if cache and env.get(cache, None) is not None:
            # use the cache from the upstream filter
            self.LOG.info('Using %s memcache for caching token', cache)
            self._cache = env.get(cache)
        else:
            # use Keystone memcache
            self._cache = memorycache.get_client(memcache_servers)
        self._cache_initialized = True


    def _conf_get(self, name):
        # try config from paste-deploy first
        if name in self.conf:
            return self.conf[name]
        else:
            return CONF.keystone_policy[name]

    def _build_KeystoneContext(self, environ):
        """Extract the identity from the Keystone auth component."""
        self.logger.debug("VVV %s" % environ.get('HTTP_X_TENANT', None))
        if environ.get('HTTP_X_IDENTITY_STATUS') != 'Confirmed':
            return
        user_id = environ.get('HTTP_X_USER_ID', None)
        user_name =  environ.get('HTTP_X_USER', None)
        tenant_id = environ.get('HTTP_X_TENANT_ID', None)
        tenant_name = environ.get('HTTP_X_TENANT', None)
        roles = [r.strip() for r in environ.get('HTTP_X_ROLES', '').split(',')]
        ctx = context.Context(user_id, tenant_id, user_name = user_name,
                tenant_name = tenant_name, roles=roles)
        return ctx

    def __call__(self, env, start_response):
        if not self._cache_initialized:
            self._init_cache(env)

        if not self._conf_get('stub_mode'):
            self.create_middleware_header(env)
        return self.app(env, start_response)

    def create_middleware_header(self, env):
        context = self._build_KeystoneContext(env)
        self.logger.debug("Printing Identity %s" % context)
        self._add_headers(env, {'X-Authorized': 'NO'})
        self._add_headers(env, {'context':context})
        self._add_headers(env, {'getpolicy':self.get_policy})

    def get_admin_token(self):
        """Return admin token, possibly fetching a new one.

        :return admin token id
        :raise ServiceError when unable to retrieve token from keystone

        """

        self.admin_token, self.policy = self._request_admin_token()

        return self.admin_token, self.policy

    def _get_http_connection(self):
        if self.auth_protocol == 'http':
            return self.http_client_class(self.auth_host, self.auth_port)
        else:
            return self.http_client_class(self.auth_host,
                                          self.auth_port,
                                          self.key_file,
                                          self.cert_file)

    def _http_request(self, method, path,**kwargs):
        """HTTP request helper used to make unspecified content type requests.

        :param method: http method
        :param path: relative request url
        :return (http response object)
        :raise ServerError when unable to communicate with keystone

        """
        conn = self._get_http_connection()

        RETRIES = 3
        retry = 0
        while True:
            try:
                conn.request(method, path, **kwargs)
                response = conn.getresponse()
                body = response.read()
                break
            except Exception, e:
                if retry == RETRIES:
                        self.LOG.error('HTTP connection exception: %s' % e)
                        raise ServiceError('Unable to communicate with keystone')
                self.logger.warn('Retrying on HTTP connection exception: %s' % e)
                time.sleep(2.0 ** retry / 2)
                retry += 1
            finally:
                conn.close()

        return response, body

    def _json_request(self, method, path, body=None, additional_headers=None):
        """HTTP request helper used to make json requests.

        :param method: http method
        :param path: relative request url
        :param body: dict to encode to json as request body. Optional.
        :param additional_headers: dict of additional headers to send with
                                   http request. Optional.
        :return (http response object, response body parsed as json)
        :raise ServerError when unable to communicate with keystone

        """
        conn = self._get_http_connection()

        kwargs = {
            'headers': {
                'Content-type': 'application/json',
                'Accept': 'application/json',
            },
        }

        if additional_headers:
            kwargs['headers'].update(additional_headers)

        if body:
            kwargs['body'] = jsonutils.dumps(body)

        full_path = self.auth_admin_prefix + path
        try:
            conn.request(method, full_path, **kwargs)
            response = conn.getresponse()
            body = response.read()
        except Exception, e:
            self.logger.error('HTTP connection exception: %s' % e)
            raise ServiceError('Unable to communicate with keystone')
        finally:
            conn.close()

        try:
            data = jsonutils.loads(body)
        except ValueError:
            self.logger.debug('Keystone did not return json-encoded body')
            data = {}

        return response, data

    def _request_admin_token(self):
        """Retrieve new token as admin user from keystone.

        :return token id upon success
        :raises ServerError when unable to communicate with keystone

        """
        params = {
            'auth': {
                'passwordCredentials': {
                    'username': self.admin_user,
                    'password': self.admin_password,
                },
                'tenantName': self.admin_tenant_name,
                'service': self.service
            }
        }

        response, data = self._json_request('POST',
                                            '/v2.0/tokens',
                                            body=params)

        try:
            token = data['access']['token']['id']
            policy = data['access']['policy']
            assert token
            return token, policy
        except (AssertionError, KeyError):
            self.logger.warn("Unexpected response from keystone service: %s", data)
            raise ServiceError('invalid json response')

    def get_policy(self):
        token, policy = self.get_admin_token()
        if self._cache is not None:
            return self._cache_get(policy, token)
        return None

    def _fetch_policy(self, token, policy_meta):
        """ Fetch policy from Keystone """
        headers = {'X-Auth-Token': token}
        response, data = self._json_request('GET',
                                            '/v2.0/policies/%s' % policy_meta['id'],
                                            additional_headers=headers)

        if response.status == 200:
            return data['policy']
        if response.status == 404:
            self.logger.warn("Fetching policy %s failed %s", policy_meta['id'])
            raise InvalidPolicy('authorization failed')
        if response.status == 401:
            self.logger.info('Keystone rejected admin token %s, resetting', headers)
            self.admin_token = None
        else:
            self.logger.error('Bad response code while fetching policy: %s' %
                      response.status)

    def _cache_get(self, policy, token):
        """Return policy information from cache.
        """

        if self._cache and policy:
            if self._memcache_security_strategy is None:
                key = CACHE_KEY_TEMPLATE
                timestamp, serialized = self._cache.get(key)
            else:
                keys = memcache_crypt.derive_keys(
                    token,
                    self._memcache_secret_key,
                    self._memcache_security_strategy)
                cache_key = CACHE_KEY_TEMPLATE % (
                    memcache_crypt.get_cache_key(keys))
                raw_cached = self._cache.get(cache_key)
                try:
                    serialized = memcache_crypt.unprotect_data(keys,
                                                               raw_cached)
                except Exception:
                    msg = 'Failed to decrypt/verify cache data'
                    self.LOG.exception(msg)
                    serialized = None

            if serialized is None:
                return None

            cached = json.loads(serialized)
            if timestamp == policy[0]['timestamp']:
                self.LOG.debug('Policy is synced')
                return cached
            else:
                self.LOG.debug('Cached Policy %s seems expired', policy)
                new_policy = self._fetch_policy(token, policy[0])
                self._cache_store(new_policy)

    def _cache_store(self, policy):
        """Store value into memcache.

        data may be the string 'invalid' or a tuple like (data, expires)

        """
        serialized_data = json.dumps(policy['blob'])
        if self._memcache_security_strategy is None:
            cache_key = CACHE_KEY_TEMPLATE
            data_to_store = (policy['timestamp'],serialized_data)
        else:
            keys = memcache_crypt.derive_keys(
                token,
                self._memcache_secret_key,
                self._memcache_security_strategy)
            cache_key = CACHE_KEY_TEMPLATE % memcache_crypt.get_cache_key(keys)
            data_to_store = memcache_crypt.protect_data(keys, serialized_data)
        try:
            self._cache.set(cache_key,
                            data_to_store,
                            time=self.policy_cache_time)
        except(TypeError):
            self._cache.set(cache_key,
                            data_to_store,
                            timeout=self.policy_cache_time)

    def _header_to_env_var(self, key):
        """Convert header to wsgi env variable.

        :param key: http header name (ex. 'X-Auth-Token')
        :return wsgi env variable name (ex. 'HTTP_X_AUTH_TOKEN')

        """
        return 'HTTP_%s' % key.replace('-', '_').upper()

    def _add_headers(self, env, headers):
        """Add http headers to environment."""
        for (k, v) in headers.iteritems():
            env_key = self._header_to_env_var(k)
            env[env_key] = v



def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return Authorize(app, conf)
    return auth_filter


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return Authorize(None, conf)
