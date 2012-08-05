# Copyright 2011 OpenStack LLC.
# Copyright 2011 Nebula, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from keystoneclient import base


class Policy(base.Resource):
    """Represents an access control policy."""
    def __repr__(self):
        return '<Policy %s>' % self._info

    def delete(self):
        return self.manager.delete(self)


class PolicyManager(base.ManagerWithFind):
    """Manager class for manipulating access control policies."""
    resource_class = Policy

    def get(self, policy):
        return self._get('/policies/%s' % base.getid(policy), 'policy')

    def list(self, endpoint=None):
        """List all available access control policies."""
        path = '/policies'
        if endpoint is not None:
            path = '%s?endpoint_id=%s' % (path, base.getid(endpoint))
        return self._list(path, 'policies')

    def create(self, blob, type, endpoint):
        """Create an access control policy."""
        params = {
            'policy': {
                'policy': blob,
                'type': type,
                'endpoint_id': base.getid(endpoint),
            }
        }
        return self._create('/policies', params, 'policy')

    def update(self, policy, blob=None, type=None, endpoint=None):
        """Update an access control policy."""
        ref = {}
        if blob is not None:
            ref['policy'] = blob
        if type is not None:
            ref['type'] = type
        if endpoint is not None:
            ref['endpoint_id'] = base.getid(endpoint)

        return self._update(
            '/policies/%s' % base.getid(policy),
            {'policy': ref},
            'policy')

    def delete(self, policy):
        """Delete an access control policy."""
        return self._delete('/policies/%s' % base.getid(policy))
