"""
Tests command line utility
"""
import unittest
import subprocess
import sys
from tests.base_tests import BaseTestHueApi
from tests.config_test import sample_queries


class TestCommandLineScript(BaseTestHueApi):
    def setUp(self):
        super().setUp()
        # Needs ong_hue_api to be installed
        self.cmd = "python -m ong_hue_api.__main__"
        self.default_file = self.full_path("Consulta1.csv")

    def execute(self, cmdline: str):
        cmdLine = f" -p \"{self.path}\" " + cmdline
        if self.keyring.username:
            cmdLine += f" -u \"{self.keyring.username}\" " + cmdline
        # process = subprocess.run(self.cmd + " " + cmdline, capture_output=True)
        process = subprocess.Popen(self.cmd + cmdline, stdout=subprocess.PIPE, shell=True)
        for c in iter(lambda: process.stdout.read(1), b""):
            sys.stdout.write(c.decode('latin1'))
    pass

    def test_help(self):
        """This should display help and download nothing"""
        self.execute("")
        self.verify_download(self.default_file, -1, self.default_file)

    def test_simple_query(self):
        """Example of simple download of just 1 query"""
        query = sample_queries['simple_query']
        self.execute(f"-s \"{query.query}\"")
        self.verify_download(self.default_file, query.expected_size, self.default_file)

    def test_simple_query_named(self):
        """Example of simple download of just 1 query with a given name"""
        query = sample_queries['simple_query']
        self.execute(f"-s \"{query.query}\" -n ejemplo")
        expected = self.full_path("ejemplo.csv")
        self.verify_download(expected, query.expected_size, expected)

    def test_simple_query_variables(self):
        """Example of simple download of just 1 query with params"""
        query = sample_queries['simple_query_params']
        variable_str = " ".join(f"-k {k} -v \"{v}\"" for k, v in query.variables.items())
        self.execute(f"-s \"{query.query}\" {variable_str}")
        expected = self.default_file
        self.verify_download(expected, query.expected_size, expected)

    def test_simple_query_chunked(self):
        """Example of simple download of just 1 query"""
        query = sample_queries['simple_query']
        self.execute(f"-s \"{query.query}\" -c 50")
        expected = self.default_file
        self.verify_download(expected, query.expected_size, expected)

    def test_download_files(self):
        """Example of simple download of just 1 query"""
        cmd_line = ""
        expected_file = []
        expected_size = []
        for query in sample_queries['sample_file_downloads']:
            expected_file.append(self.full_path(query.expected_filename))
            expected_size.append(query.expected_size)
            cmd_line += f" -s \"{query.query}\""
        self.execute(cmd_line)
        self.verify_download(expected_file, expected_size, expected_file)

    def tearDown(self):
        # Do nothing (so files are not deleted)
        pass


if __name__ == '__main__':
    unittest.main()
