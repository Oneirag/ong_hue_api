"""
Tests command line utility
Tests everything twice: executing subprocesses and executing directly code simulating command line arguments
"""
import unittest
import subprocess
import sys
from tests.base_tests import BaseTestHueApi
from tests.config_test import sample_queries, test_editor
from ong_hue_api.__main__ import main
import shlex


class TestCommandLineScript(BaseTestHueApi):
    def setUp(self):
        super().setUp()
        # Needs ong_hue_api to be installed
        self.cmd = "python -m ong_hue_api.__main__"
        self.default_file = self.full_path("Consulta1.csv")

    def get_commandline(self, cmdline: str) -> str:
        """Generates full command line"""
        retval = f" -e \"{test_editor}\" -p \"{self.path}\" " + cmdline
        if self.keyring.username:
            retval += f" -u \"{self.keyring.username}\" "
        retval = self.cmd + retval
        return retval

    def execute(self, cmdline):
        """Executes command twice: first one using subprocess and then using direct code call"""
        yield self.__execute_subprocess(cmdline)
        yield self.__execute_code(cmdline)

    def __execute_code(self, cmdline: str):
        """Execute using the main function and simulating argv from cmdline"""
        cmd = self.get_commandline(cmdline)
        argv = shlex.split(cmd)
        sys.argv = argv[2:]
        main()

    def __execute_subprocess(self, cmdline: str):
        """Execute using subprocess"""
        # process = subprocess.Popen(self.get_commandline(cmdline), stdout=subprocess.PIPE, shell=True)
        cmd = self.get_commandline(cmdline)
        cmd = shlex.split(cmd)  # Passing arguments split into list avoids problems with special characters
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        for c in iter(lambda: process.stdout.read(1), b""):
            sys.stdout.write(c.decode('latin1'))
    pass

    def test_help(self):
        """This should display help and download nothing"""
        execution = self.execute("")
        # First execution with subprocess, should not leave any file
        next(execution)
        self.verify_download(self.default_file, -1, self.default_file)
        # Second execution with code, raises exception...
        with self.assertRaises(SystemExit):     # This is the exception raised with bad code
            next(execution)
        # ...and should not leave any file
        self.verify_download(self.default_file, -1, self.default_file)

    def test_simple_query(self):
        """Example of simple download of just 1 query"""
        query = sample_queries['simple_query']
        for _ in self.execute(f"-s \"{query.query}\""):
            self.verify_download(self.default_file, query.expected_size, self.default_file)
            self.remove_temp_files()

    def test_simple_query_named(self):
        """Example of simple download of just 1 query with a given name"""
        query = sample_queries['simple_query']
        for _ in self.execute(f"-s \"{query.query}\" -n ejemplo"):
            expected = self.full_path("ejemplo.csv")
            self.verify_download(expected, query.expected_size, expected)
            self.remove_temp_files()

    def test_simple_query_variables(self):
        """Example of simple download of just 1 query with params"""
        query = sample_queries['simple_query_params']
        variable_str = " ".join(f"-k {k} -v \"{v}\"" for k, v in query.variables.items())
        for _ in self.execute(f"-s \"{query.query}\" {variable_str}"):
            expected = self.default_file
            self.verify_download(expected, query.expected_size, expected)
            self.remove_temp_files()

    def test_simple_query_chunked(self):
        """Example of simple download of just 1 query"""
        query = sample_queries['simple_query']
        for _ in self.execute(f"-s \"{query.query}\" -c 50"):
            expected = self.default_file
            self.verify_download(expected, query.expected_size, expected)
            self.remove_temp_files()

    def test_download_files(self):
        """Example of downloading files from hdfs or s3"""
        cmd_line = ""
        expected_file = []
        expected_size = []
        for query in sample_queries['sample_file_downloads']:
            expected_file.append(self.full_path(query.expected_filename))
            expected_size.append(query.expected_size)
            cmd_line += f" -s \"{query.query}\""
            for _ in self.execute(cmd_line):
                self.verify_download(expected_file, expected_size, expected_file)
                self.remove_temp_files()

    def tearDown(self):
        # Comment next line to do nothing (so files are not deleted)
        super().remove_temp_files()
        pass


if __name__ == '__main__':
    unittest.main()
