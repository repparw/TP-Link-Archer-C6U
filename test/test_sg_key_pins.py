"""Optional RSA public-key pin verification for TplinkRouterSG."""
from hashlib import sha256
from unittest.mock import MagicMock, patch

import pytest

from tplinkrouterc6u import TplinkRouterSG, ClientException
from Crypto.PublicKey import RSA


def _spki_fingerprint(pub_der: bytes) -> str:
    """SHA-256 over DER SubjectPublicKeyInfo, mirroring the client."""
    def der_len(n):
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b
    alg = bytes([0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
                 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00])
    bitstring = bytes([0x03]) + der_len(len(pub_der) + 1) + b"\x00" + pub_der
    spki_inner = alg + bitstring
    spki = bytes([0x30]) + der_len(len(spki_inner)) + spki_inner
    return sha256(spki).hexdigest()


def _mock_key_responses(pwd_key: RSA.RsaKey, auth_key: RSA.RsaKey, seq=100):
    pwd = MagicMock()
    pwd.json.return_value = {"data": {"password": [
        format(pwd_key.n, "x"), format(pwd_key.e, "x")]}}

    auth = MagicMock()
    auth.json.return_value = {"data": {"seq": seq, "key": [
        format(auth_key.n, "x"), format(auth_key.e, "x")]}}

    login = MagicMock()
    login.json.return_value = {"data": "encrypted"}
    login.headers = {}
    login.text = "mock"

    return [pwd, auth, login]


class TestSGKeyPins:
    def test_matching_pins_authorize(self):
        keypair = RSA.generate(2048)
        responses = _mock_key_responses(keypair, keypair)

        client = TplinkRouterSG(
            "http://192.168.0.1", "testpassword",
            password_key_pin=_spki_fingerprint(keypair.publickey().export_key(format="DER")),
            auth_key_pin="sha256:" + _spki_fingerprint(
                keypair.publickey().export_key(format="DER")).upper())

        # Matching pins let the handshake proceed past key verification into
        # the (mocked) login exchange.
        with patch("tplinkrouterc6u.client.sg.post", side_effect=responses):
            try:
                client.authorize()
            except Exception as exc:
                # The mocked login blob is not decryptable; the important
                # assertion is that we got PAST the pin checks.
                assert "pin mismatch" not in str(exc), str(exc)
                assert "Failed to get" not in str(exc), str(exc)

    def test_substituted_password_key_fails_closed(self):
        served = RSA.generate(2048)
        pinned = RSA.generate(2048)
        responses = _mock_key_responses(served, served)

        client = TplinkRouterSG(
            "http://192.168.0.1", "testpassword",
            password_key_pin=_spki_fingerprint(pinned.publickey().export_key(format="DER")))

        with patch("tplinkrouterc6u.client.sg.post", side_effect=responses):
            with pytest.raises(ClientException, match="password key pin mismatch"):
                client._request_pwd_keys()

    def test_substituted_auth_key_fails_closed(self):
        served = RSA.generate(2048)
        pinned = RSA.generate(2048)
        responses = _mock_key_responses(served, served)

        client = TplinkRouterSG(
            "http://192.168.0.1", "testpassword",
            auth_key_pin=_spki_fingerprint(pinned.publickey().export_key(format="DER")))

        client._pwdNN, client._pwdEE = format(served.n, "x"), format(served.e, "x")
        with patch("tplinkrouterc6u.client.sg.post", side_effect=responses[1:2]):
            with pytest.raises(ClientException, match="auth key pin mismatch"):
                client._request_auth_keys()

    def test_malformed_pin_rejected_at_construction(self):
        with pytest.raises(ValueError, match="64 hex"):
            TplinkRouterSG("http://192.168.0.1", "testpassword",
                           password_key_pin="tooshort")
        with pytest.raises(ValueError, match="hexadecimal"):
            TplinkRouterSG("http://192.168.0.1", "testpassword",
                           auth_key_pin="z" * 64)

    def test_empty_pins_disable_verification(self):
        client = TplinkRouterSG("http://192.168.0.1", "testpassword")
        assert client._password_key_pin == ""
        assert client._auth_key_pin == ""

    def test_rotation_handled_by_updating_pin(self):
        old_key = RSA.generate(2048)
        client = TplinkRouterSG(
            "http://192.168.0.1", "testpassword",
            password_key_pin=_spki_fingerprint(old_key.publickey().export_key(format="DER")))

        rotated = RSA.generate(2048)
        responses = _mock_key_responses(rotated, rotated)
        client._pwdNN = client._pwdEE = ""
        with patch("tplinkrouterc6u.client.sg.post", side_effect=responses):
            with pytest.raises(ClientException, match="pin mismatch"):
                client._request_pwd_keys()

        client._password_key_pin = client._normalize_pin(
            _spki_fingerprint(rotated.publickey().export_key(format="DER")),
            "password_key_pin")
        responses = _mock_key_responses(rotated, rotated)
        with patch("tplinkrouterc6u.client.sg.post", side_effect=responses):
            client._request_pwd_keys()  # no exception
