"""Test the rest api"""
import unittest

from ong_hue_api.hue_rest_api import HueRest


class TestHueRestApi(unittest.TestCase):

    def test_list_tables(self):
        hue = HueRest()
        # df = hue.execute_query("show databases", calculate_rows=False)
        df = hue.execute_query("show databases")
        print(df)

if __name__ == '__main__':
    unittest.main()