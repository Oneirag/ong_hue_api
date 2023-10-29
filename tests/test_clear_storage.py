"""
Same tests as test_hue_code_api and test_hue_command_line_api, but clearing keyring storage beforehand
"""

import unittest

from ong_hue_api.internal_storage import KeyringStorage
from tests.config_test import test_username, test_server, test_password


class TestKeyringStorage(unittest.TestCase):

    def test_new_credentials(self):
        """Tests that test credentials are valid"""
        kr = KeyringStorage(username=test_username, check=False)
        kr.delete(all=True)
        kr.set_hue_server(server=test_server)
        kr.set_password(password=test_password)
        valid = kr.check(password=test_password)
        self.assertTrue(valid)


if __name__ == '__main__':
    kr = KeyringStorage()
    kr.delete(all=True)
    unittest.main()
