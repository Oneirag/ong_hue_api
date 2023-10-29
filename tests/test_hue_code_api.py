"""
General functionality_tests of ong_hue_api
"""
from __future__ import annotations

import unittest

from ong_hue_api.hue import Hue
from ong_hue_api.utils import get_filename
from tests.base_tests import BaseTestHueApi
from ong_hue_api.post_process_hue import csv2df, df2openxls


class TestHueCodeApi(BaseTestHueApi):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.hue = Hue(debug=True, keyring_storage=cls.keyring, editor_type=cls.editor)

    def setUp(self):
        super().setUp()
        self.simple_sql_df = self.sample_queries['simple_query_df']
        self.simple_sql = self.sample_queries["simple_query"]
        self.bad_sql = self.sample_queries["bad_query"]
        self.execute_kwargs = dict(name="test", format="csv", path=self.path)
        self.expected_file = get_filename(**self.execute_kwargs)

    def execute(self, query: str = None, **kwargs):
        query = query or self.simple_sql
        default_kwargs = self.execute_kwargs.copy()
        default_kwargs.update(kwargs)
        default_kwargs['query'] = query
        return self.hue.execute_query(**default_kwargs)

    def test_simple_download(self):
        """Test a simple file download"""
        retval = self.execute(self.simple_sql.query, format=self.simple_sql.format)
        self.verify_download(retval, self.simple_sql.expected_size,
                             get_filename(self.path, name="test", format=self.simple_sql.format))

    def test_simple_download_df(self):
        """Test a simple file download and process into a pandas DataFrame"""
        query = self.simple_sql_df
        retval = self.execute(query.query)
        self.verify_download(retval, query.expected_size, self.expected_file)
        df = csv2df(retval, convert_dates=False)
        df2openxls(df, "Libro1", "Hoja1")

    def test_simple_download_chunked(self):
        """Test a simple file download with expected size"""
        retval = self.execute(self.simple_sql.query, chunk_rows=50)
        self.verify_download(retval, self.simple_sql.expected_size,
                             self.expected_file)

    def test_bad_query(self):
        """Tests that a bad formatted query returns None"""
        retval = self.execute(self.bad_sql.query)
        self.assertIsNone(retval, "Query should not provide a file")
        self.verify_download(self.expected_file, self.bad_sql.expected_size,
                             self.expected_file)

    def test_simple_download_variables(self):
        """Tests some downloads with variables"""
        query = self.sample_queries["simple_query_params"]
        retval = self.execute(query.query, variables=query.variables)
        self.verify_download(retval, query.expected_size,
                             self.expected_file)

    def test_list_files(self):
        """List the files in a certain dir"""
        files = self.hue.filebrowser(self.hdfs_path)
        self.assertFalse(len(files) == 0, "No files where found")
        print(sorted(files.keys()))
        files_filtered = self.hue.filebrowser(self.hdfs_path, filter="2023")
        print(sorted(files_filtered.keys()))
        self.assertTrue(len(files) > len(files_filtered), "No filtering was done")

    def test_download_file(self):
        """Downloads two files and tests that the size is the expected one"""
        for query_config in self.sample_queries["sample_file_downloads"]:
            expected_filename = self.full_path(query_config.expected_filename)
            retval = self.hue.download_file(query_config.query, path=self.path,
                                            local_filename=query_config.expected_filename)
            self.verify_download(retval, query_config.expected_size, expected_filename)
        self.remove_temp_files()

    def remove_temp_files(self):
        # Keep temp files
        pass
        super().remove_temp_files()


if __name__ == '__main__':
    unittest.main()
