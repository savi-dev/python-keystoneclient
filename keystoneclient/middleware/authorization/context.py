import logging


LOG=logging.getLogger(__name__)

class Context(object):
      def __init__(self, user_id, tenant_id, is_admin=None,
                 roles=None, domain_id=None, **kwargs):
        if kwargs:
            LOG.warn(_('Arguments dropped when creating '
                       'context: %s'), kwargs)
        self.roles = roles or []
        self.user = user_id
        self.tenant = tenant_id
        self.domain = domain_id
        if is_admin is None:
            self.is_admin = 'admin' in [x.lower() for x in self.roles]
        elif self.is_admin and 'admin' not in [x.lower() for x in self.roles]:
            self.roles.append('admin')

      @property
      def project_id(self):
          return self.tenant

      @property
      def tenant_id(self):
          return self.tenant

      @tenant_id.setter
      def tenant_id(self, tenant_id):
          self.tenant = tenant_id

      @property
      def user_id(self):
          return self.user

      @user_id.setter
      def user_id(self, user_id):
          self.user = user_id

      @property
      def domain_id(self):
          return self.domain

      @domain_id.setter
      def domain_id(self, domain_id):
          self.domain=domain_id
      
      def to_dict(self):
          return {'user_id': self.user_id,
                'tenant_id': self.tenant_id,
                'project_id': self.project_id,
                'domain_id':self.domain_id,
                'is_admin': self.is_admin,
                'roles': self.roles
                }

      @classmethod
      def from_dict(cls, values):
          return cls(**values)


