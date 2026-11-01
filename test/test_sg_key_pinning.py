"""Opt-in RSA key pinning on the SG transport; no router access or writes."""
from hashlib import sha256
from unittest import TestCase
from unittest.mock import Mock, patch

from Crypto.PublicKey.RSA import construct

from tplinkrouterc6u.client.sg import TplinkRouterSG
from tplinkrouterc6u.common.exception import ClientException


# Fixed public-only RSA key already used by the SG client's signature tests.
N = (
    'ca8f1711cc27576fb0dae0d7df1b6a90465e8ea31ccf46b0004f4c60f6617df'
    '8fa147502e45353b4d3f8ad38cb9aee9a77d33973ce3d7d681bc2fb0ae242e631'
)
E = '010001'


def expected_fingerprint():
    key = construct((int(N, 16), int(E, 16)))
    return sha256(key.export_key(format='DER')).hexdigest()


def reply(field, value):
    response = Mock()
    response.json.return_value = {'data': {field: value}}
    return response


class TestSGPins(TestCase):
    def test_absent_pins_preserve_legacy_behavior(self):
        client = TplinkRouterSG('http://router.invalid', 'pw')
        self.assertIsNone(client._password_key_pin)
        self.assertIsNone(client._auth_key_pin)

    def test_bad_pin_rejected_before_network_io(self):
        with patch('tplinkrouterc6u.client.sg.post') as post:
            for pin in ('bad', 'x' * 64, '00' * 33, 'sha256:', 1234):
                with self.subTest(pin=pin), self.assertRaises(ValueError):
                    TplinkRouterSG('http://router.invalid', 'pw',
                                   password_key_pin=pin)
            post.assert_not_called()

    def test_spki_fingerprint_matches_pycryptodome_der(self):
        # Independent ASN.1 DER/SPKI reference (same as Go x509.MarshalPKIXPublicKey).
        self.assertEqual(
            TplinkRouterSG._key_fingerprint(N, E),
            '4951e6aaa9d960092f30cd89e0ca6b1f9ea91708a963652e03f2aa55feb44cac')
        client = TplinkRouterSG(
            'http://router.invalid', 'pw',
            password_key_pin='SHA256:' + expected_fingerprint().upper(),
            auth_key_pin=expected_fingerprint().upper())
        self.assertEqual(client._password_key_pin, expected_fingerprint())
        self.assertEqual(client._auth_key_pin, expected_fingerprint())

    @patch('tplinkrouterc6u.client.sg.post')
    def test_both_matching_pins_allow_key_exchange(self, post):
        auth = reply('key', [N, E])
        auth.json.return_value['data']['seq'] = 17
        post.side_effect = [reply('password', [N, E]), auth]
        fp = expected_fingerprint()
        router = TplinkRouterSG('http://router.invalid', 'pw',
                                password_key_pin=fp, auth_key_pin=fp)
        router._request_pwd_keys()
        router._request_auth_keys()
        self.assertEqual(post.call_count, 2)

    @patch('tplinkrouterc6u.client.sg.post')
    def test_password_pin_mismatch_never_sends_login(self, post):
        post.return_value = reply('password', [N, E])
        router = TplinkRouterSG(
            'http://router.invalid', 'pw',
            password_key_pin='00' * 32)
        with self.assertRaisesRegex(ClientException, 'password RSA key pin mismatch'):
            router.authorize()
        self.assertEqual(post.call_count, 1)
        self.assertIn('login?form=keys', post.call_args.args[0])

    @patch('tplinkrouterc6u.client.sg.post')
    def test_auth_pin_mismatch_never_sends_login(self, post):
        auth = reply('key', [N, E])
        auth.json.return_value['data']['seq'] = 5
        post.side_effect = [reply('password', [N, E]), auth]
        router = TplinkRouterSG(
            'http://router.invalid', 'pw',
            password_key_pin=expected_fingerprint(),
            auth_key_pin='ff' * 32)
        with self.assertRaisesRegex(ClientException, 'auth RSA key pin mismatch'):
            router.authorize()
        self.assertEqual(post.call_count, 2)
        self.assertTrue(all('form=login' not in args.args[0]
                            for args in post.call_args_list))

    @patch('tplinkrouterc6u.client.sg.post')
    def test_rotation_requires_explicit_pin_update(self, post):
        post.return_value = reply('password', [N, E])
        old_pin = '00' * 32
        router = TplinkRouterSG('http://router.invalid', 'pw',
                                password_key_pin=old_pin)
        with self.assertRaisesRegex(ClientException, 'pin mismatch'):
            router._request_pwd_keys()
        updated = TplinkRouterSG('http://router.invalid', 'pw',
                                 password_key_pin=expected_fingerprint())
        updated._request_pwd_keys()
        self.assertEqual(post.call_count, 2)
