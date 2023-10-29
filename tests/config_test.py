"""
Configuration for tests: queries, expected returns, username and password
"""

from tests import QueryConfig

test_username = "demo"                                              # Use None to use current logged-in user
test_password = "demo"                                              # Use None to use stored value in the keyring
test_editor = "hive"                                                # Type of editor for tests. Use None for impala
test_server = "https://demo.gethue.com/"                            # Use None to use the one stored in the keyring


sample_queries = {
    "simple_query_df":
        QueryConfig(query="SELECT * FROM default.visit_csv",
                    expected_size=262),
    "simple_query":
        QueryConfig(query="SELECT * FROM default.visit_csv",
                    expected_size=262, format="csv"),
    "simple_query_pandas":
        QueryConfig(query="SELECT * FROM default.visit_csv",
                    expected_size=5568, format="pandas"),
    "bad_query":
        QueryConfig(query="SELECT * FROM default.non_existing_table",
                    expected_size=-1),  # Negative size: file is expected not to have been created
    "simple_query_params":
        QueryConfig(
            query="SELECT * FROM default.visit_csv where user_id= '${user_id}'",
            expected_size=58, variables=dict(user_id="u4")),
    "sample_file_downloads": [
        QueryConfig(query="s3a://demo-gethue/data/web_logs/index_data.csv",
                    expected_size=6199593, expected_filename="index_data.csv"),
    ]
}

sample_hdfs_path = "s3a://demo-gethue/data/web_logs"

