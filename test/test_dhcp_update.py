"""No hardware access: verify wire format and ambiguous identity behavior."""
from json import loads
from unittest import TestCase
from urllib.parse import parse_qs

from tplinkrouterc6u.client.sg import TplinkRouterSG
from tplinkrouterc6u.common.exception import ClientException


class TestDHCPUpdate(TestCase):
    def client(self, rows):
        class FakeRouter(TplinkRouterSG):
            def __init__(self):
                super().__init__('http://router', 'password')
                self.requests = []

            def request(self, path, data, **kwargs):
                self.requests.append((path, data))
                if data == 'operation=load':
                    return {'list': rows}
                return None

        return FakeRouter()

    def test_updates_in_place_and_preserves_extra_fields(self):
        old = {'mac': 'AA-BB-CC-DD-EE-FF', 'ip': '192.168.0.2',
               'comment': 'old', 'enable': 'on', 'vendor_extension': 'keep'}
        router = self.client([old])
        router.update_ipv4_reservation('aa:bb:cc:dd:ee:ff',
                                       ipaddr='192.168.0.8',
                                       comment='', enable=False)
        path, body = router.requests[-1]
        args = parse_qs(body)
        self.assertEqual(args['operation'], ['update'])
        self.assertEqual(args['key'], ['AA-BB-CC-DD-EE-FF'])
        self.assertIn('form=reservation', path)
        self.assertEqual(loads(args['old'][0]), old)
        updated = loads(args['new'][0])
        self.assertEqual(updated['ip'], '192.168.0.8')
        self.assertEqual(updated['comment'], '')
        self.assertEqual(updated['enable'], 'off')
        self.assertEqual(updated['vendor_extension'], 'keep')

    def test_unknown_mac_does_not_write(self):
        router = self.client([])
        with self.assertRaises(ClientException):
            router.update_ipv4_reservation('aa:bb:cc:dd:ee:ff', comment='nope')
        self.assertEqual(len(router.requests), 1)

    def test_duplicate_mac_fails_closed(self):
        old = {'mac': 'AA-BB-CC-DD-EE-FF', 'ip': '192.168.0.2'}
        router = self.client([old, old])
        with self.assertRaises(ClientException):
            router.update_ipv4_reservation('aa:bb:cc:dd:ee:ff', enable=True)
        self.assertEqual(len(router.requests), 1)

    def test_omitted_fields_keep_current_values(self):
        old = {'mac': 'AA-BB-CC-DD-EE-FF', 'ip': '192.168.0.2',
               'comment': 'old', 'enable': 'on'}
        router = self.client([old])
        router.update_ipv4_reservation('AA-BB-CC-DD-EE-FF', ipaddr='192.168.0.3')
        args = parse_qs(router.requests[-1][1])
        new = loads(args['new'][0])
        self.assertEqual(new['comment'], 'old')
        self.assertEqual(new['enable'], 'on')
