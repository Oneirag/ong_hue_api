"""
Configuration for tests: queries, expected returns, username and password
"""

from tests import QueryConfig

test_username = "demo"                                              # Use None to use current logged-in user
test_password = "demo"                                              # Use None to use stored value in the keyring
test_editor = "hive"                                                # Type of editor for tests. Use None for impala
test_server = "https://demo.gethue.com/"                            # Use None to use the one stored in the keyring

table_name = "default.ong_hive_test_csv"

sample_queries = {
    "simple_query_df":
        QueryConfig(query=f"SELECT * FROM {table_name}",
                    expected_size=1588),
    "simple_query":
        QueryConfig(query=f"SELECT * FROM {table_name}",
                    expected_size=1588, format="csv"),
    "simple_query_pandas":
        QueryConfig(query=f"SELECT * FROM {table_name}",
                    expected_size=1588, format="pandas"),
    "bad_query":
        QueryConfig(query=f"SELECT * FROM non_existing_table",
                    expected_size=-1),  # Negative size: file is expected not to have been created
    "simple_query_params":
        QueryConfig(
            query=f"SELECT * FROM {table_name} where number= ${{number}}",
            expected_size=88, variables=dict(number=25)),
    "sample_file_downloads": [
        QueryConfig(query="s3a://demo-gethue/data/web_logs/index_data.csv",
                    expected_size=6199593, expected_filename="index_data.csv"),
    ]
}

sample_hdfs_path = "s3a://demo-gethue/data/web_logs"

