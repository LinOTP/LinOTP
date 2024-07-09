import json
import unittest

from werkzeug.test import Client
from werkzeug.wrappers import Response

from linotp.middlewares.trusted_proxy_handler import TrustedProxyHandler


class TestTrustedProxyHandler(unittest.TestCase):
    def setUp(self):
        # Mock WSGI application
        def environ_returning_application(environ, start_response):
            serializable_environ = {}
            for key, value in environ.items():
                try:
                    json.dumps(value)
                    serializable_environ[key] = value
                except (TypeError, ValueError):
                    serializable_environ[key] = str(value)

            response = Response(json.dumps(serializable_environ), status=200)
            return response(environ, start_response)

        self.environ_returning_app = environ_returning_application

    def test_trusted_proxy(self):
        # List of trusted proxies

        trusted_proxies = ["192.168.1.1"]
        app = TrustedProxyHandler(self.environ_returning_app, trusted_proxies)
        client = Client(app, Response)

        # Simulate a request from a trusted proxy
        environ = {
            "REMOTE_ADDR": "192.168.1.1",
            "HTTP_X_FORWARDED_FOR": "1.2.3.4",
        }
        response = client.get("/", environ_overrides=environ)
        environ_in_app = json.loads(response.data)

        self.assertEqual(response.status_code, 200)

        self.assertEqual(environ_in_app.get("REMOTE_ADDR"), "1.2.3.4")
        self.assertEqual(environ_in_app.get("HTTP_X_FORWARDED_FOR"), "1.2.3.4")

    def test_untrusted_proxy(self):
        # List of trusted proxies
        trusted_proxies = ["192.168.1.1"]
        app = TrustedProxyHandler(self.environ_returning_app, trusted_proxies)
        client = Client(app, Response)

        # Simulate a request from an untrusted proxy
        environ = {
            "REMOTE_ADDR": "10.0.0.2",
            "HTTP_X_FORWARDED_FOR": "1.2.3.4",
        }
        response = client.get("/", environ_overrides=environ)
        environ_in_app = json.loads(response.data)

        self.assertEqual(response.status_code, 200)

        self.assertEqual(environ_in_app.get("REMOTE_ADDR"), "10.0.0.2")
        self.assertEqual(environ_in_app.get("HTTP_X_FORWARDED_FOR"), "1.2.3.4")
        self.assertNotIn("werkzeug.proxy_fix.orig", environ_in_app)

    def test_trusted_proxy_not_set(self):
        # List of trusted proxies
        trusted_proxies = []
        app = TrustedProxyHandler(self.environ_returning_app, trusted_proxies)
        client = Client(app, Response)

        # Simulate a request from an untrusted proxy
        environ = {
            "REMOTE_ADDR": "10.0.0.2",
            "HTTP_X_FORWARDED_FOR": "1.2.3.4",
        }
        response = client.get("/", environ_overrides=environ)
        environ_in_app = json.loads(response.data)

        self.assertEqual(response.status_code, 200)

        self.assertEqual(environ_in_app.get("REMOTE_ADDR"), "10.0.0.2")
        self.assertEqual(environ_in_app.get("HTTP_X_FORWARDED_FOR"), "1.2.3.4")
        self.assertNotIn("werkzeug.proxy_fix.orig", environ_in_app)
