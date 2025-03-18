"""
Necesita:
pip install requests ong_utils[credentials] ong_utils[jwt] pandas
"""
import logging
import os
import time
from pathlib import Path
from tkinter.messagebox import showerror
from typing import Tuple

import pandas as pd
import requests
from ong_utils import InternalStorage
from ong_utils import OngTimer
from ong_utils import get_current_user
from ong_utils.ui import OngFormDialog
from requests.utils import cookiejar_from_dict
from tqdm import tqdm
from dotenv import load_dotenv



class CredentialsManager:
    """Class that manages username and password, storing it securely in keyring"""
    __PASSWORD_KEY = "password"
    __HUE_TOKEN_KEY = "hue_token"
    __HUE_COOKIES_KEY = "hue_cookies"
    __HUE_REFRESH_TOKEN_KEY = "hue_refresh_token"

    def __init__(self):
        self.storage = InternalStorage(__file__)
        self.username = get_current_user()
        self.password = self.storage.get_value(self.__PASSWORD_KEY)
        self.token = self.storage.get_value(self.__HUE_TOKEN_KEY)
        self.refresh_token = self.storage.get_value(self.__HUE_REFRESH_TOKEN_KEY)
        self.cookies = self.storage.get_value(self.__HUE_COOKIES_KEY)

    def store_token_cookies(self, token: str, refresh_token: str, cookies: dict):
        """Stores token securely"""
        self.storage.store_value(self.__HUE_TOKEN_KEY, token)
        self.storage.store_value(self.__HUE_COOKIES_KEY, cookies)
        self.storage.store_value(self.__HUE_REFRESH_TOKEN_KEY, refresh_token)
        self.cookies = cookies
        self.token = token
        self.refresh_token = refresh_token

    def get_user_password(self) -> Tuple[str, str]:
        """Gets a tuple with current username and password. Tries to locate it in internal storage,
        otherwise asks for password in a gui"""

        if not self.password:
            credentials = OngFormDialog(title="Hue login",
                                        description="Input your username and domain password"
                                        ).add_domain_user_password(validate_os=True).show()
            self.password = credentials['password']
        self.storage.store_value(self.__PASSWORD_KEY, self.password)
        return self.username, self.password

    def clean_stored_password(self):
        """Removes previously stored values"""
        self.storage.remove_stored_value(self.__PASSWORD_KEY)
        self.storage.remove_stored_value(self.__HUE_TOKEN_KEY)
        self.storage.remove_stored_value(self.__HUE_COOKIES_KEY)
        self.token = None
        self.password = None
        self.cookies = None
        self.refresh_token = None


class HueRest:
    """
    Class to manage connection to a hue server using its rest api
    """
    # Loads .env file from current directory
    load_dotenv(Path.cwd() / ".env")
    HUE_SERVER = os.getenv("HUE_REST_API_SERVER")
    session = requests.Session()
    # LOG_LEVEL = logging.DEBUG
    LOG_LEVEL = os.getenv("HUE_REST_API_LOGGING", logging.INFO)
    # Number of rows that are downloaded per request
    # ROWS_PER_REQUEST = 50000
    ROWS_PER_REQUEST = int(os.getenv("HUE_REST_API_ROWS", 100000))   #100k, no idea if speeds up

    def get_url(self, endpoint: str) -> str:
        if not endpoint.startswith("/"):
            endpoint = f"/{endpoint}"
        return f"{self.HUE_SERVER}{endpoint}"

    def __showerror_and_exit(self, msg_title: str, msg_content: str, log_msg: str, exit_code: int):
        showerror("No autorizado", )
        self.credentials.clean_stored_password()
        if log_msg:
            self.logger.error(log_msg)
        self.credentials.get_user_password()
        exit(exit_code)

    def __raise_not_auth_exception(self, exit_code: int):
        self.__showerror_and_exit("Unauthorized", "User does not have permission to perform the query. "
                                                   "Review your credentials and login again", log_msg="",
                                  exit_code=exit_code)

    def __post(self, endpoint: str, data: dict, raise_error_on_not_auth: bool = True) -> Tuple[requests.Response, dict]:
        response = self.session.post(self.get_url(endpoint), data=data)
        if response.status_code == 401 and raise_error_on_not_auth:
            self.__raise_not_auth_exception(response.status_code)
        return response, response.json()


    def __init__(self):
        """logs in"""
        if not self.HUE_SERVER:
            raise ValueError("No hue server configured. Please add it to HUE_REST_API_SERVER environmental variable")
        logging.basicConfig(level=self.LOG_LEVEL)
        self.logger = logging
        self.progress_bar = None

        def login_ok():
            self.logger.info(f'Token: {self.token[:10]}...')
            self.session.headers = {
                'Authorization': f'Bearer {self.token}',
                "Content-Type": "application/x-www-form-urlencoded"
            }
            self.credentials.store_token_cookies(self.token, self.refresh_token, self.cookies)

        self.credentials = CredentialsManager()
        # Check if token is expired
        self.token = None
        self.refresh_token = None
        if self.credentials.token and (requests.post(self.get_url("/api/v1/token/verify/"),
                                             data=dict(token=self.credentials.token)).status_code == 200):
            self.token = self.credentials.token
            self.cookies = self.credentials.cookies
            self.session.cookies = cookiejar_from_dict(self.cookies)
            login_ok()
            return
        if self.credentials.refresh_token:
            # use refresh_token
            response_refresh = self.session.post(self.get_url("/api/v1/token/refresh/"),
                                                 data=dict(refresh=self.credentials.refresh_token))
            if response_refresh.status_code == 200:
                json = response_refresh.json()
                self.cookies = response_refresh.cookies.get_dict()
                self.token = json['access']
                self.refresh_token = self.credentials.refresh_token
                login_ok()
                return

        # Standard login with username and password
        username, password = self.credentials.get_user_password()

        data = {
            'username': username,
            'password': password,
        }

        response, json = self.__post("/api/v1/token/auth", data=data)
        self.cookies = self.session.cookies.get_dict()
        if response.status_code == 200:
            self.logger.info("Login ok")
        else:
            self.__showerror_and_exit("Invalid credentials",
                                      "Credentials are invalid. Exiting... "
                                      "Execute again a insert correct credentials",
                                      log_msg=f"Invalid credentials: {response.status_code} {response.text}",
                                      exit_code=-1)
        self.token = json['access']
        self.refresh_token = json['refresh']
        login_ok()

    def calculate_rows(self, query: str) -> int:
        """Calculates number of rows of a given query"""
        try:
            df = self.execute_query(f"with t as ( {query} ) select count(*) from t limit 1",
                                    calculate_rows=False, raise_exception_on_error=True)
        except Exception as e:
            return -1
        if df.empty:
            return 0
        return int(df.iat[0, 0])


    def execute_query(self, sql: str, calculate_rows: bool=True, raise_exception_on_error: bool=False) -> pd.DataFrame | None:
        """Executes the given SQL, returning None in case of any error"""
        with OngTimer(msg=sql, logger=self.logger):
            params = {
                'statement': sql,
            }
            if calculate_rows:
                total_rows = self.calculate_rows(sql)
                self.progress_bar = tqdm(total=total_rows, unit='iB', unit_scale=True)
            else:
                total_rows = None
                # progress_bar = None

            response, resp_content = self.__post("/api/v1/editor/execute/impala", data=params)
            if response.status_code != 200 or resp_content['status'] != 0:
                error_msg = f"SQL query '{sql}' has errors:\n{resp_content['message']}"
                self.logger.error(error_msg)
                if raise_exception_on_error:
                    raise ValueError(error_msg)
                else:
                    showerror("Query Error", error_msg)
                return
            self.logger.debug(response.status_code)
            self.logger.debug(response.text)

            data = {
                'operationId': resp_content['history_uuid'],
                # Not default, but will return much more results per query ;)
                "rows": self.ROWS_PER_REQUEST,
            }
            if self.progress_bar:
                self.progress_bar.update(0)

            for n_repeat in range(5):
                response, response_content = self.__post('/api/v1/editor/check_status',
                                                         data=data
                                                         )
                self.logger.debug(response.status_code)
                self.logger.debug(response.text)
                if response_content['query_status']['status'] == "available":
                    break
                time.sleep(min(30, 2 ** n_repeat))  # Wait up to 30 seconds per sleep
            else:
                showerror("Query error", "Query results are not available")
                return None

            response, response_content = self.__post('/api/v1/editor/fetch_result_data', data=data)
            self.logger.debug(response.status_code)
            self.logger.debug(response.text)
            all_data = list()
            while True:
                columns = [meta['name'] for meta in response_content['result']['meta']]
                all_data.extend(response_content['result']['data'])
                all_data_len = len(all_data)
                pct = f"{all_data_len/total_rows:.2%}" if total_rows else ""
                logging.debug(f"{all_data_len:,} {pct}")
                if self.progress_bar:
                    self.progress_bar.update(all_data_len)
                if not response_content['result']['has_more']:
                    break
                response, response_content = self.__post('/api/v1/editor/fetch_result_data', data=data)
            df = pd.DataFrame(all_data, columns=columns)
            if calculate_rows:
                self.progress_bar = None
            return df


if __name__ == '__main__':
    # creds = CredentialsManager()
    # creds.clean_stored_password()

    hue = HueRest()

    # df = hue.execute_query("select * from pepe")
    for file, query in {
            # f"select * from dl_datagov.audit_queries_origin_table where Ucase(nam_user)= '{os.getenv('username')}' "
            # f"order by dah_time_start desc "
            # f"limit 100",


            # "SELECT count(*) FROM dl_mercados_cons.cons_pos_cartera_power_allegro WHERE dat_report='2023-09-15'",
            # 'select * from dl_modelos.buss_pro_simopt_margen limit 98676',
            # "SELECT * FROM dl_mercados_cons.cons_pos_cartera_power_allegro WHERE dat_report='2023-09-15'",
    }.items():
        if not Path(file).exists():
            df = hue.execute_query(query)
            df.to_csv(file, index=False)
            print(df.head())
            print(df.shape)
