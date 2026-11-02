"""The SG response distinguishes router session expiry from network timeouts."""
import json
from unittest.mock import patch

import pytest

from tplinkrouterc6u.client.sg import TplinkRouterSG
from tplinkrouterc6u.common.exception import ClientError


@pytest.mark.parametrize("envelope", [
    {"success": False, "errorcode": "timeout"},
    {"success": False, "data": {"errorcode": "timeout"}},
])
def test_explicit_session_timeout_is_exposed(envelope):
    client = TplinkRouterSG("http://router.invalid", "password")
    client._logged = True
    client._stok = "session"
    client._sysauth = "cookie"

    with patch.object(client, "_aes_encrypt", return_value="encrypted"), \
         patch.object(client, "_build_request_signature", return_value="sig"), \
         patch.object(client, "_aes_decrypt", return_value=json.dumps(envelope)), \
         patch("tplinkrouterc6u.client.sg.post") as post:
        post.return_value.json.return_value = {"data": "encrypted"}
        post.return_value.text = '{"data":"encrypted"}'
        with pytest.raises(ClientError, match=r"errorcode timeout"):
            client.request("admin/forwarding?form=virtualServers",
                           "operation=update&key=test")
        post.assert_called_once()


def test_other_router_error_is_not_reported_as_session_expiry():
    client = TplinkRouterSG("http://router.invalid", "password")
    client._logged = True
    client._stok = "session"
    client._sysauth = "cookie"

    with patch.object(client, "_aes_encrypt", return_value="encrypted"), \
         patch.object(client, "_build_request_signature", return_value="sig"), \
         patch.object(client, "_aes_decrypt", return_value=json.dumps({
             "success": False, "errorcode": "invalid_request",
         })), \
         patch("tplinkrouterc6u.client.sg.post") as post:
        post.return_value.json.return_value = {"data": "encrypted"}
        post.return_value.text = '{"data":"encrypted"}'
        with pytest.raises(ClientError) as caught:
            client.request("admin/status?form=all", "operation=read")
        assert "errorcode timeout" not in str(caught.value)
