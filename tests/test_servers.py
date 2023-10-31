import unittest
from ong_hue_api.internal_storage import check_server


class HueServerTests(unittest.TestCase):

    bad_servers = ("", None, "google.com", "https://www.google.com", "https://google.com:1235/hola/?result=pepe#sitio")
    good_servers = ("https://demo.gethue.com/hue/editor/?type=6", "https://demo.gethue.com")

    #
    def test_check_hue_servers(self):
        """Tests that servers are properly identified as good/bad hue servers"""
        for bad_server in self.bad_servers:
            print(f"Checking {bad_server=}")
            valid = check_server(bad_server)
            self.assertFalse(valid, f"Server {bad_server} was incorrectly identified as valid")

        for good_server in self.good_servers:
            print(f"Checking {good_server=}")
            valid = check_server(good_server)
            self.assertTrue(valid, f"Server {good_server} was incorrectly identified as NOT valid")


if __name__ == '__main__':
    unittest.main()
