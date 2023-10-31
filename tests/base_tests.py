from __future__ import annotations

import os
import unittest

from tests.config_test import sample_queries, sample_hdfs_path, test_username, test_server, test_password, test_editor
from ong_hue_api.internal_storage import KeyringStorage


def get_iterable(x):
    """If arg x is not iterable (it is an integer, string or None), turns it into tuple"""
    if isinstance(x, (str, int)) or x is None:
        return (x,)
    else:
        return x


def remove_temp_files(path: str):
    for f in os.listdir(path):
        full_path_f = os.path.join(path, f)
        if os.path.isfile(full_path_f) and not f.endswith(".log"):
            os.remove(full_path_f)


class BaseTestHueApi(unittest.TestCase):

    path = None
    keyring = None
    editor = None

    @classmethod
    def setUpClass(cls):
        cls.path = os.path.join(os.getcwd(), "data")
        os.makedirs(cls.path, exist_ok=True)
        remove_temp_files(cls.path)
        cls.keyring = KeyringStorage(username=test_username, check=False)
        if test_password:
            cls.keyring.set_password(test_password)
        if test_server:
            cls.keyring.set_hue_server(test_server)
        cls.keyring.check_and_ask()
        cls.editor = test_editor

    def setUp(self):
        self.sample_queries = sample_queries
        self.hdfs_path = sample_hdfs_path

    def full_path(self, filename: str) -> str:
        return os.path.join(self.path, filename)

    def verify_download(self, retval: str | list, expected_size: int | list, expected_filename: str | list):
        """
        Verifies that a file was downloaded where expected and with the expected size
        :param retval: the reval of the execution, which is the name of the downloaded file. Either str or list of str
        :param expected_size: expected size in bytes of the file. Either int or list of ints
        :param expected_filename: the expected name of the file. Either str or list of strs
        :return: None
        """
        for single_retval, single_expected_size, single_expected_filename in zip(get_iterable(retval),
                                                                                 get_iterable(expected_size),
                                                                                 get_iterable(expected_filename)):
            if single_expected_size >= 0:
                # file must exist
                self.assertEqual(single_retval, single_expected_filename,
                                 f"File {single_retval} could not be downloaded")
                self.assertTrue(os.path.isfile(single_retval),
                                f"File {single_retval} was not created")
                self.assertEqual(single_expected_size, os.path.getsize(single_retval),
                                 f"Incorrect file size for {single_retval}")
            else:
                # File must NOT exist:
                self.assertFalse(os.path.isfile(single_retval),
                                 f"File {single_retval} was created but it should not")

    def tearDown(self):
        self.remove_temp_files()

    def remove_temp_files(self):
        remove_temp_files(self.path)
