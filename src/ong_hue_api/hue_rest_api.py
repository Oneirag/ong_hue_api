"""
Necesita:
pip install requests ong_utils[credentials] ong_utils[jwt] pandas
"""

from __future__ import annotations

import getpass
import logging
import os
import time
from enum import Enum
from pathlib import Path
from typing import Tuple

import pandas as pd
import requests
from ong_utils import InternalStorage
from ong_utils import OngTimer
from ong_utils import get_current_user
from requests.utils import cookiejar_from_dict
from tqdm import tqdm
from dotenv import load_dotenv


class HueRestError(RuntimeError):
    """Raised by HueRest / HueRestCli in CLI mode to signal an error to the user
    instead of popping up a graphical dialog. The exception message is intended
    to be human-readable."""


class UIMode(str, Enum):
    """UI interaction mode for HueRest. GUI keeps the legacy behavior
    (tkinter dialogs and exit on auth failure). CLI uses stdin/logger and
    raises HueRestError on errors instead of calling exit()."""

    GUI = "gui"
    CLI = "cli"


class _BaseUi:
    """Minimal interface used by HueRest. Concrete implementations are
    _GuiUi (legacy tkinter) and _CliUi (stdin + logger + exceptions)."""

    def prompt_credentials(self, username: str) -> Tuple[str, str]:
        raise NotImplementedError

    def show_error(
        self, title: str, message: str, *, fatal: bool = False, exit_code: int = -1
    ) -> None:
        """Display an error. In CLI mode this always raises HueRestError
        regardless of `fatal`. In GUI mode, when `fatal=True` the process
        is terminated via exit()."""
        raise NotImplementedError

    def notify(self, message: str) -> None:
        """Optional success/finish notification."""
        raise NotImplementedError


class _GuiUi(_BaseUi):
    """Default UI: tkinter dialogs and (in __init__ paths) exit() on fatal auth errors."""

    def __init__(self, owner: "HueRest"):
        self._owner = owner

    def prompt_credentials(self, username: str) -> Tuple[str, str]:
        # Imported lazily so that importing this module on a headless box
        # never tries to import tkinter.
        from ong_utils.ui import OngFormDialog

        credentials = (
            OngFormDialog(
                title="Hue login", description="Input your username and domain password"
            )
            .add_domain_user_password(validate_os=True)
            .show()
        )
        return credentials["username"], credentials["password"]

    def show_error(
        self, title: str, message: str, *, fatal: bool = False, exit_code: int = -1
    ) -> None:
        import tkinter as _tk
        from tkinter.messagebox import showerror

        # Show a modal error to the user
        try:
            root = _tk.Tk()
            # Hide the root window but keep it as parent for the dialog
            root.withdraw()
            try:
                root.attributes("-topmost", True)
            except Exception:
                # Some tkinter builds may not support attributes; ignore
                pass
            showerror(title, message, parent=root)
            try:
                root.destroy()
            except Exception:
                pass
        except Exception:
            # Fallback to logging if tkinter/messagebox fails for any reason
            self._owner.logger.error(f"{title}: {message}")

        if fatal:
            exit(exit_code)

    def notify(self, message: str) -> None:
        # No-op by design: success notifications are not requested.
        return


class _CliUi(_BaseUi):
    """Headless UI: stdin for credentials, logger for output, exceptions for errors."""

    def __init__(self, owner: "HueRest"):
        self._owner = owner

    def prompt_credentials(self, username: str) -> Tuple[str, str]:
        prompted = input(f"Hue user [{username}]: ")
        prompted = prompted.strip() or username
        password = getpass.getpass("Hue password: ")
        return prompted, password

    def show_error(
        self, title: str, message: str, *, fatal: bool = False, exit_code: int = -1
    ) -> None:
        # In CLI mode we never call exit(); we always raise so the caller
        # can handle the error. `fatal` is accepted for API symmetry but ignored.
        self._owner.logger.error(f"{title}: {message}")
        raise HueRestError(message)

    def notify(self, message: str) -> None:
        self._owner.logger.info(message)


class CredentialsManager:
    """Class that manages username and password, storing it securely in keyring"""

    __PASSWORD_KEY = "password"
    __HUE_TOKEN_KEY = "hue_token"
    __HUE_COOKIES_KEY = "hue_cookies"
    __HUE_REFRESH_TOKEN_KEY = "hue_refresh_token"

    def __init__(self, ui: _BaseUi | None = None):
        self.storage = InternalStorage(__file__)
        self.username = get_current_user()
        self.password = self.storage.get_value(self.__PASSWORD_KEY)
        self.token = self.storage.get_value(self.__HUE_TOKEN_KEY)
        self.refresh_token = self.storage.get_value(self.__HUE_REFRESH_TOKEN_KEY)
        self.cookies = self.storage.get_value(self.__HUE_COOKIES_KEY)
        # UI used to prompt for credentials when none are stored. Defaults to a
        # GUI ui for backward compatibility; HueRest passes its own ui.
        self._ui: _BaseUi = ui if ui is not None else _GuiUi(None)  # type: ignore[arg-type]

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
        otherwise asks for password via the configured UI"""

        if not self.password:
            username, password = self._ui.prompt_credentials(self.username)
            self.username = username
            self.password = password
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
    ROWS_PER_REQUEST = int(
        os.getenv("HUE_REST_API_ROWS", 100000)
    )  # 100k, no idea if speeds up

    def get_url(self, endpoint: str) -> str:
        if not endpoint.startswith("/"):
            endpoint = f"/{endpoint}"
        return f"{self.HUE_SERVER}{endpoint}"

    def __showerror_and_exit(
        self, msg_title: str, msg_content: str, log_msg: str, exit_code: int
    ):
        # Clear any stored secrets and ask user for new credentials
        self.credentials.clean_stored_password()
        if log_msg:
            self.logger.error(log_msg)

        # Ask for new credentials. In CLI mode this will raise on failure;
        # we let that propagate so the caller (script) decides what to do.
        username, password = self.credentials.get_user_password()

        # Try to authenticate with the provided credentials. If successful, update session and continue.
        try:
            data = {"username": username, "password": password}
            response = self.session.post(self.get_url("/api/v1/token/auth"), data=data)
            if response.status_code == 200:
                json = response.json()
                self.cookies = self.session.cookies.get_dict()
                self.token = json.get("access")
                self.refresh_token = json.get("refresh")
                # Apply authorization header and persist tokens
                if self.token:
                    self.session.headers.update(
                        {
                            "Authorization": f"Bearer {self.token}",
                            "Content-Type": "application/x-www-form-urlencoded",
                        }
                    )
                try:
                    self.credentials.store_token_cookies(
                        self.token, self.refresh_token, self.cookies
                    )
                except Exception:
                    self.logger.debug(
                        "Could not store token/cookies in credentials manager"
                    )
                # Successful re-login; return to caller to continue operation
                return
            else:
                # Authentication failed: show error and exit (GUI) / raise (CLI)
                self._ui.show_error(
                    "Invalid credentials",
                    "Credentials are invalid. Exiting...",
                    fatal=True,
                    exit_code=exit_code,
                )
                return
        except HueRestError:
            raise
        except Exception as e:
            self.logger.error(f"Error while authenticating: {e}")
            self._ui.show_error(
                "Authentication error",
                f"Error while authenticating: {e}",
                fatal=True,
                exit_code=exit_code,
            )
            return

    def __raise_not_auth_exception(self, exit_code: int):
        self.__showerror_and_exit(
            "Unauthorized",
            "User does not have permission to perform the query. "
            "Review your credentials and login again",
            log_msg="",
            exit_code=exit_code,
        )

    def __post(
        self, endpoint: str, data: dict, raise_error_on_not_auth: bool = True
    ) -> Tuple[requests.Response, dict]:
        response = self.session.post(self.get_url(endpoint), data=data)
        if response.status_code == 401 and raise_error_on_not_auth:
            self.__raise_not_auth_exception(response.status_code)
        return response, response.json()

    def __init__(self, ui: UIMode = UIMode.GUI):
        """logs in. Pass ui=UIMode.CLI to get stdin prompts, logger-based error
        reporting and HueRestError exceptions instead of GUI dialogs / exit()."""
        if not self.HUE_SERVER:
            raise ValueError(
                "No hue server configured. Please add it to HUE_REST_API_SERVER environmental variable"
            )
        logging.basicConfig(level=self.LOG_LEVEL)
        self.logger = logging
        self.progress_bar = None

        # Resolve UI mode. _CliUi is always available (no tkinter needed);
        # _GuiUi is only constructed when actually used.
        self._ui_mode = UIMode(ui) if not isinstance(ui, UIMode) else ui
        if self._ui_mode is UIMode.CLI:
            self._ui: _BaseUi = _CliUi(self)
        else:
            self._ui = _GuiUi(self)

        def login_ok():
            self.logger.info(f"Token: {self.token[:10]}...")
            self.session.headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            self.credentials.store_token_cookies(
                self.token, self.refresh_token, self.cookies
            )

        self.credentials = CredentialsManager(ui=self._ui)
        # Check if token is expired
        self.token = None
        self.refresh_token = None
        if self.credentials.token and (
            requests.post(
                self.get_url("/api/v1/token/verify/"),
                data=dict(token=self.credentials.token),
            ).status_code
            == 200
        ):
            self.token = self.credentials.token
            self.cookies = self.credentials.cookies
            self.session.cookies = cookiejar_from_dict(self.cookies)
            login_ok()
            return
        if self.credentials.refresh_token:
            # use refresh_token
            response_refresh = self.session.post(
                self.get_url("/api/v1/token/refresh/"),
                data=dict(refresh=self.credentials.refresh_token),
            )
            if response_refresh.status_code == 200:
                json = response_refresh.json()
                self.cookies = response_refresh.cookies.get_dict()
                self.token = json["access"]
                self.refresh_token = self.credentials.refresh_token
                login_ok()
                return

        # Standard login with username and password
        username, password = self.credentials.get_user_password()

        data = {
            "username": username,
            "password": password,
        }

        response, json = self.__post("/api/v1/token/auth", data=data)
        self.cookies = self.session.cookies.get_dict()
        if response.status_code == 200:
            self.logger.info("Login ok")
        else:
            self.__showerror_and_exit(
                "Invalid credentials",
                "Credentials are invalid. Exiting... "
                "Execute again a insert correct credentials",
                log_msg=f"Invalid credentials: {response.status_code} {response.text}",
                exit_code=-1,
            )
        self.token = json["access"]
        self.refresh_token = json["refresh"]
        login_ok()

    def calculate_rows(self, query: str) -> int:
        """Calculates number of rows of a given query"""
        try:
            df = self.execute_query(
                f"with t as ( {query} ) select count(*) from t limit 1",
                calculate_rows=False,
                raise_exception_on_error=True,
            )
        except Exception as e:
            return -1
        if df.empty:
            return 0
        return int(df.iat[0, 0])

    def execute_query(
        self,
        sql: str,
        calculate_rows: bool = True,
        raise_exception_on_error: bool = False,
    ) -> pd.DataFrame | None:
        """Executes the given SQL, returning None in case of any error.
        In CLI mode errors are reported through the configured logger and (when
        raise_exception_on_error=True) also raised as HueRestError."""
        with OngTimer(msg=sql, logger=self.logger):
            params = {
                "statement": sql,
            }
            if calculate_rows:
                total_rows = self.calculate_rows(sql)
                self.progress_bar = tqdm(total=total_rows, unit="iB", unit_scale=True)
            else:
                total_rows = None
                # progress_bar = None

            response, resp_content = self.__post(
                "/api/v1/editor/execute/impala", data=params
            )
            if response.status_code != 200 or resp_content["status"] != 0:
                error_msg = f"SQL query '{sql}' has errors:\n{resp_content['message']}"
                self.logger.error(error_msg)
                if raise_exception_on_error:
                    raise HueRestError(error_msg)
                else:
                    self._ui.show_error("Query Error", error_msg)
                return
            self.logger.debug(response.status_code)
            self.logger.debug(response.text)

            data = {
                "operationId": resp_content["history_uuid"],
                # Not default, but will return much more results per query ;)
                "rows": self.ROWS_PER_REQUEST,
            }
            if self.progress_bar:
                self.progress_bar.update(0)

            for n_repeat in range(5):
                response, response_content = self.__post(
                    "/api/v1/editor/check_status", data=data
                )
                self.logger.debug(response.status_code)
                self.logger.debug(response.text)
                if response_content["query_status"]["status"] == "available":
                    break
                time.sleep(min(30, 2**n_repeat))  # Wait up to 30 seconds per sleep
            else:
                err = "Query results are not available"
                self.logger.error(err)
                if raise_exception_on_error:
                    raise HueRestError(err)
                self._ui.show_error("Query error", err)
                return None

            response, response_content = self.__post(
                "/api/v1/editor/fetch_result_data", data=data
            )
            self.logger.debug(response.status_code)
            self.logger.debug(response.text)
            all_data = list()
            while True:
                columns = [meta["name"] for meta in response_content["result"]["meta"]]
                all_data.extend(response_content["result"]["data"])
                all_data_len = len(all_data)
                pct = f"{all_data_len / total_rows:.2%}" if total_rows else ""
                logging.debug(f"{all_data_len:,} {pct}")
                if self.progress_bar:
                    self.progress_bar.update(all_data_len)
                if not response_content["result"]["has_more"]:
                    break
                response, response_content = self.__post(
                    "/api/v1/editor/fetch_result_data", data=data
                )
            df = pd.DataFrame(all_data, columns=columns)
            if calculate_rows:
                self.progress_bar = None
            self.logger.debug("Query finished: %d rows", len(df))
            return df


if __name__ == "__main__":
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
