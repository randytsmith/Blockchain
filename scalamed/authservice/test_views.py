from authservice import views
from django.test import TestCase
from rest_framework.test import APIClient
from scalamed.logging import log


class ViewsTestCase(TestCase):

    def setUp(self):
        self.client = APIClient()
        # log.setLevel(100)

    def tearDown(self):
        log.setLevel(30)

    def test_register(self):
        body = {
            'email': 'jim.raynor@terran.scu',
            'password': 'wXqkw5UCLOqxrNQrl2Xe2sgNR4JtOFjR'
        }

        response = self.client.put('/auth/register', body, format='json')
        self.assertEqual(response.status_code, 201)
