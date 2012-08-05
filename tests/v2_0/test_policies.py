import urlparse
import json

import httplib2

from keystoneclient.v2_0 import policies
from tests import utils


class PolicyTests(utils.TestCase):
    def setUp(self):
        super(PolicyTests, self).setUp()
        self.TEST_REQUEST_HEADERS = {
            'X-Auth-Token': 'aToken',
            'User-Agent': 'python-keystoneclient',
        }
        self.TEST_POST_HEADERS = {
            'Content-Type': 'application/json',
            'X-Auth-Token': 'aToken',
            'User-Agent': 'python-keystoneclient',
        }
        self.TEST_POLICIES = {
            'policies': [
                {
                    'id': '1',
                    'endpoint_id': '2',
                    'policy': '{"default": true}',
                    'type': 'application/json',
                },
                {
                    'id': '3',
                    'endpoint_id': '4',
                    'policy': '{"default": false}',
                    'type': 'application/json',
                }
            ],
        }

    def test_create(self):
        req = self.TEST_POLICIES['policies'][0].copy()
        del req['id']
        resp = httplib2.Response({
            'status': 201,
            'body': json.dumps({'policy': self.TEST_POLICIES['policies'][0]}),
        })

        httplib2.Http.request(urlparse.urljoin(self.TEST_URL,
                              'v2.0/policies'),
                              'POST',
                              body=json.dumps({'policy': req}),
                              headers=self.TEST_POST_HEADERS) \
            .AndReturn((resp, resp['body']))
        self.mox.ReplayAll()

        policy = self.client.policies.create(
            endpoint=req['endpoint_id'],
            blob=req['policy'],
            type=req['type'])
        self.assertTrue(isinstance(policy, policies.Policy))
        self.assertEqual(policy.id, self.TEST_POLICIES['policies'][0]['id'])
        self.assertEqual(policy.endpoint_id, req['endpoint_id'])
        self.assertEqual(policy.policy, req['policy'])
        self.assertEqual(policy.type, req['type'])

    def test_delete(self):
        resp = httplib2.Response({
            'status': 200,
            'body': '',
        })
        httplib2.Http.request(urlparse.urljoin(self.TEST_URL,
                              'v2.0/policies/1'),
                              'DELETE',
                              headers=self.TEST_REQUEST_HEADERS) \
            .AndReturn((resp, resp['body']))
        self.mox.ReplayAll()

        self.client.policies.delete('1')

    def test_get(self):
        ref = self.TEST_POLICIES['policies'][0]
        resp = httplib2.Response({
            'status': 200,
            'body': json.dumps({
                'policy': ref,
            }),
        })
        httplib2.Http.request(urlparse.urljoin(self.TEST_URL,
                              'v2.0/policies/%s' % ref['id']),
                              'GET',
                              headers=self.TEST_REQUEST_HEADERS) \
            .AndReturn((resp, resp['body']))
        self.mox.ReplayAll()

        policy = self.client.policies.get(ref['id'])
        self.assertTrue(isinstance(policy, policies.Policy))
        self.assertEqual(policy.id, ref['id'])
        self.assertEqual(policy.endpoint_id, ref['endpoint_id'])
        self.assertEqual(policy.policy, ref['policy'])
        self.assertEqual(policy.type, ref['type'])

    def test_list(self):
        resp = httplib2.Response({
            'status': 200,
            'body': json.dumps(self.TEST_POLICIES),
        })

        httplib2.Http.request(urlparse.urljoin(self.TEST_URL,
                              'v2.0/policies'),
                              'GET',
                              headers=self.TEST_REQUEST_HEADERS) \
            .AndReturn((resp, resp['body']))
        self.mox.ReplayAll()

        policy_list = self.client.policies.list()
        [self.assertTrue(isinstance(r, policies.Policy)) for r in policy_list]

    def test_list_for_endpoint(self):
        resp = httplib2.Response({
            'status': 200,
            'body': json.dumps({
                'policies': [self.TEST_POLICIES['policies'][0]]
            }),
        })

        endpoint_id = self.TEST_POLICIES['policies'][0]['endpoint_id']
        httplib2.Http.request(urlparse.urljoin(self.TEST_URL,
                              'v2.0/policies?endpoint_id=%s' % endpoint_id),
                              'GET',
                              headers=self.TEST_REQUEST_HEADERS) \
            .AndReturn((resp, resp['body']))
        self.mox.ReplayAll()

        policy_list = self.client.policies.list(endpoint=endpoint_id)
        [self.assertTrue(isinstance(r, policies.Policy)) for r in policy_list]
