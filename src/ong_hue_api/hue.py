from __future__ import annotations

import logging
import urllib.parse
import os

import pandas as pd
import requests
from tqdm import tqdm


from ong_hue_api import *
if is_windows:
    from win11toast import notify
from ong_hue_api.internal_storage import KeyringStorage
from ong_hue_api.logs import create_logger
from ong_hue_api.payload_utils import format_payload
from ong_hue_api.utils import handle_exceptions, get_query_chunked, remove_header, new_uuid, timestamp, \
    get_csfrmiddlewaretoken, get_filename, add_variables, check_content_type, is_hdfs_s3


class Hue:
    """Main class to manage Hue interface"""

    # Endpoints used in the HUE API
    _endpoint_default_app = "desktop/api2/user_preferences/default_app"     # Used for check that login data is valid
    _endpoint_get_config = [
        "desktop/api2/get_config/",  # Old hue versions
        "api/v1/get_config/",  # In the demo version
    ]
    _endpoint_autocomplete_ = [
        "notebook/api/autocomplete/",  # Used for listing DBs
        "api/v1/editor/autocomplete/"   # New version (but previous works)
    ]
    _endpoint_login = "hue/accounts/login"
    _endpoint_create_impala = "desktop/api2/context/namespaces/{editor}"
    _endpoint_create_session = "notebook/api/create_session"
    _endpoint_create_notebook = "notebook/api/create_notebook"
    _endpoint_editor = "hue/editor"
    _endpoint_execute_impala = "notebook/api/execute/{editor}"
    _endpoint_download = "notebook/download"
    _endpoint_fetch_data = [ "notebook/api/fetch_result_data",
                             "api/v1/editor/fetch_result_data", # New hue (demo version)
                             ]
    _endpoint_check_status = "notebook/api/check_status"
    _endpoint_jobs = "desktop/api2/context/clusters/jobs"
    _endpoint_logout = "accounts/logout"
    _endpoint_close_statement = "notebook/api/close_statement"
    _endpoint_filebrowser_download = "filebrowser/download"
    _endpoint_filebrowser_view = "filebrowser/view"

    # Different log levels
    _DEBUG = "debug"
    _INFO = "info"
    _WARNING = "warning"
    _ERROR = "error"
    _EXCEPTION = "exception"

    # For iter_content, chunk_size
    content_chunk_size = 1024

    @property
    def base_url(self):
        url = self.keyring_storage.hue_server
        if not url.endswith("/"):
            url += "/"
        return url

    def log(self, level: str, msg: str, exception=None, show_notification: bool | str = False):
        """
        Writes log to the logger. Use show_notification to show a toast in windows
        :param level: self._DEBUG, self._INFO, etc. or "error", "info", "debug"...
        :param msg: The message of the exception
        :param exception: an exception class to raise with the exception text, if required
        :param show_notification: False (default) to not raise notification. Ture to show notification,
         a text with the path of a file to show notification that opens the given file when clicking notification
        :return:
        """
        if self.debug or level != self._DEBUG:      # Makes it a little faster...
            getattr(self.__logger, level)(msg, stacklevel=2)
        if show_notification and self.show_notifications and is_windows:
            if isinstance(show_notification, str):
                notify(msg, on_click=show_notification)
            else:
                notify(msg)
        if exception is not None:
            raise exception(msg)

    def ajax(self, endpoint: str | list, payload=None, headers: dict = None, **kwargs) -> dict:
        """Makes an ajax request and returns the json. Raises Error if no json was returned"""
        if headers:
            self.headers.update(headers)
        if isinstance(endpoint, str):
            endpoint = [endpoint]
        for endp in endpoint:
            res = self._request(endp, payload=payload, headers=self.headers, method="POST", **kwargs, )
            try:
                json = res.json()
                return json
            except Exception as e:
                self.log(self._ERROR, f"Error requesting {endpoint}: it did not return json",
                         exception=ValueError)
        return dict()

    def _request(self, endpoint: str, method="GET", payload=None, headers=None, **kwargs) -> requests.Response:
        """Performs a request and returns the requests.Response object"""
        if payload is not None:
            method = "POST"
        endpoint = endpoint[1:] if endpoint.startswith("/") else endpoint
        url = self.base_url + endpoint
        self.log(self._DEBUG, f"Executing {method} on {url} with data={payload} and headers={headers}")
        resp = self.__requests_session.request(method, url, data=payload, headers=headers, **kwargs)
        self.log(self._DEBUG, f"Returned: {resp} with headers {resp.headers}")
        return resp

    def _get_databases(self) -> dict:
        """Gets the list of the databases that a user can access to"""
        for url in self._endpoint_autocomplete_:
            json_db = self.ajax(url,
                                payload=format_payload(snippet={"type": self.editor_type, "source": "data"},
                                                       cluster=self.impala_cluster))
            if "databases" in json_db:
                return json_db['databases']
        return dict()

    def __init__(self, force_new_login: bool = False, show_notifications: bool = True, path=None,
                 debug=True, fast: bool = True, keyring_storage: KeyringStorage = None,
                 editor_type: str = None):
        """
        Initializes hue session. First, attempts to reuse cookies from an old session,
        otherwise logs in with user and password
        :param force_new_login: True to ignore past session cookies, False (default) to try to reuse them
        :param show_notifications: True (default) to show notification toasts after downloading files, False otherwise
        :param path: directory where logs will be created. None (default) to use current dir
        :param debug: True (default) to show debug messages, False for info or above
        :param fast: True (default) to skip checks, reconnections, etc. and make process faster (but less reliable)
        :param keyring_storage: a KeyRingStorage instance to use. If None (default) a default one will be created
        :param editor_type: Name of the editor (impala, hive...). Defaults to impala
        """
        self.editor = editor_type or "impala"  # Defaults to impala
        self.show_notifications = show_notifications
        self.debug = debug
        self.__logger = create_logger(path or os.getcwd(), level=logging.DEBUG if self.debug else logging.INFO)
        # Skips check of username and server if fast is true
        self.keyring_storage = keyring_storage or KeyringStorage(self.__logger, check=not fast)
        self.keyring_storage.logger = self.__logger
        self.__requests_session = requests.Session()
        self.headers = {
            'Accept': '*/*',
            'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': self.base_url,
            'Referer': self.base_url,
            'Pragma': 'no-cache',
            'X-Requested-With': 'XMLHttpRequest',
        }
        if force_new_login:
            self.log(self._DEBUG, "Deleting previously stored cookies")
            self.keyring_storage.delete(cookies=True)
        reuse_session = False
        if self.keyring_storage.get_cookies() and not force_new_login:
            self.__requests_session.cookies.update(self.keyring_storage.get_cookies())
            self.headers["X-CSRFToken"] = self.__requests_session.cookies.get('csrftoken', "")
            try:
                res = self.ajax(self._endpoint_default_app + "?_={}".format(timestamp()))
                self._create_notebook_impala_session(force_new_login)
                reuse_session = True
            except Exception as e:
                reuse_session = False
        if reuse_session:
            self.log(self._INFO, "Reusing last session")
        else:
            self.log(self._INFO, "Invalid session: logging in again with user and password")
            # Session was not valid, get user and password
            user = self.keyring_storage.username
            password = self.keyring_storage.password
            if not self.keyring_storage.check(password):
                self.log(self._ERROR,
                         "Invalid password. Relaunch process to update it",
                         show_notification=True)
                exit(-1)
            self.notebook = None
            self.impala = None
            self.session = None
            self.log(self._INFO, "Starting login process")
            self._login(user, password)
            # Store cookies for reuse
            self.keyring_storage.set_cookies(self.__requests_session)
            self.log(self._INFO, "Login process finished")
        self.headers["X-CSRFToken"] = self.__requests_session.cookies['csrftoken']
        interpreters = self.ajax(self._endpoint_get_config)['app_config']['editor']['interpreters']
        interpreters_dict = {e['name']: e for e in interpreters}
        self.editor_cfg = interpreters_dict.get(self.editor.capitalize())
        if self.editor_cfg is None:
            raise ValueError(f"Editor of type {self.editor} not found. "
                             f"Valid editors: {','.join(list(interpreters_dict.keys()))}")
        self.log(self._DEBUG, f"Editor config: {self.editor_cfg}")
        self._create_notebook_impala_session(force_new_login)
        self.snippet_id = new_uuid()
        self.result_id = new_uuid()

    @property
    def editor_type(self) -> str:
        if hasattr(self, "editor_cfg"):
            return self.editor_cfg['type']
        else:
            return "impala"  # default value

    @property
    def session_id(self) -> str | None:
        if self.session is not None:
            return self.session['session_id']

    @property
    def impala_id(self) -> str | None:
        if self.impala is not None:
            return self.impala['id']

    @property
    def impala_cluster(self) -> str | None:
        if self.impala is not None:
            return self.impala['computes'][0]

    @property
    def notebook_uuid(self) -> str | None:
        if self.notebook:
            return self.notebook['uuid']

    @property
    def default_db(self) -> str:
        return self.databases[0]

    def _login(self, user: str, password: str):
        """Executes login, gets cookies and updates header for later queries. Raises ValueError if login failed"""

        res = self._request(self._endpoint_login)
        csrfmiddlewaretoken = get_csfrmiddlewaretoken(res)
        payload = dict(csrfmiddlewaretoken=csrfmiddlewaretoken, username=user, password=password,
                       server="LDAP", next="/")
        login_res = self._request(self._endpoint_login, payload=payload, headers=self.headers)
        if login_res.url.endswith(self._endpoint_login):
            raise ValueError("Login failed. Are username and/or password correct?")
        return login_res

    def _create_notebook_impala_session(self, force_new: bool = True):
        """Creates empty notebook, impala and session instances"""

        impala_session_notebook = self.keyring_storage.impala_session_notebook
        if not force_new and impala_session_notebook:
            for name in "impala", "session", "notebook":
                setattr(self, name, impala_session_notebook.get(name))
        else:
            self.log(self._DEBUG, "Creating notebook")
            new_notebook = self.ajax(self._endpoint_create_notebook,
                                     payload=dict(type=self.editor_type, directory_uuid=""))
            self.notebook = new_notebook['notebook']
            self.log(self._DEBUG, f"Notebook created: {self.notebook}")
            self.log(self._DEBUG, f"Creating {self.editor} session")
            impala = self.ajax(self._endpoint_create_impala.format(editor=self.editor))
            self.log(self._DEBUG, f"{self.editor.capitalize()} session created: {impala}")
            self.impala = impala[self.editor][0]
            self.notebook["id"] = None
            self.notebook["parentSavedQueryUuid"] = None
            payload = format_payload(notebook=self.notebook,
                                     session={"type": self.editor_type},
                                     cluster={"interface": self.editor, "type": "direct",
                                              "namespace": self.impala_id,
                                              "id": self.impala_id,
                                              "name": self.impala_id}
                                     )
            self.log(self._DEBUG, "Creating session")
            new_session = self.ajax(self._endpoint_create_session, payload=payload)
            self.session = new_session['session']
            self.log(self._DEBUG, f"Session created: {self.session}")
        db = self.keyring_storage.databases
        if not db:
            self.databases = self._get_databases()
            self.keyring_storage.set_databases(self.databases)
        else:
            self.databases = db
        try:
            self.keyring_storage.set_impala_session_notebook(impala=self.impala, session=self.session,
                                                             notebook=self.notebook)
        except Exception as e:
            print(e)

    def get_jobs(self) -> dict:
        """Gets the list of current impala jobs as a json"""
        self.log(self._DEBUG, "Querying list of jobs")
        jobs = self.ajax(self._endpoint_jobs, params={"_": timestamp()})
        self.log(self._DEBUG, f"Jobs received: {jobs}")
        return jobs

    def __str__(self):
        retval = []
        for name in 'ROUTEID', 'csrftoken', 'sessionid':
            retval.append(f"{name}: {self.__requests_session.cookies.get(name)}")
        for prop in "notebook_uuid", "impala_id", "session_id":
            retval.append(f"{prop}: {getattr(self, prop)}")
        return self.__class__.__name__ + ": " + ", ".join(retval)

    def logout(self):
        """Closes session"""
        self._request(self._endpoint_logout)
        self.keyring_storage.delete(cookies=True)
        self.log(self._INFO, str(self))
        # Make sure logout was a success
        if not self.__requests_session.cookies.get('ROUTEID') is None:
            self.log(self._WARNING, "Could not exit session properly")
        else:
            self.log(self._INFO, "Hue session closed and user logout")

    def __enter__(self):
        """Called upon entering the "with" block"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Called when exiting the "with" block. Needed as __del__ fails with requests"""
        pass
        # self.logout()

    def _execute_impala(self, database: str, statement: str) -> dict | None:
        """
        Executes a query with impala. Returns the payload needed for downloading result as json of csv,
        or None in case of error
        :param database: name of the database for the query
        :param statement: the SQL sentence. Variables are shown as ${variable_name}
        :return: a dict or None in case of error
        :raises: ImpalaExecuteError
        """
        result = {
            "id": self.result_id
        }
        snippet = {
            "id": self.snippet_id,
            "type": self.editor_type,
            "statement": statement, "database": database,
            "statement_raw": statement,
            "result": result,
            "variables": [],
            "properties": {"settings": []},
            "namespace": self.impala
        }
        # This is the minimal required for notebook
        notebook = {
            "id": null, "uuid": self.notebook_uuid,
            "name": "", "description": "",
            "type": "query-" + self.editor_type,
            "isSaved": false,
            "snippets": [snippet],
            "sessions": [self.session],
        }

        mydata = format_payload(notebook=notebook, snippet=snippet)
        # First: close statement and then execute impala
        self.log(self._DEBUG, "Closing statement")
        close = self.ajax(self._endpoint_close_statement, payload=mydata)
        self.log(self._DEBUG, "Statement closed")

        self.log(self._DEBUG, f"Sending query to {self.editor}")
        response_impala = self.ajax(self._endpoint_execute_impala.format(editor=self.editor), payload=mydata)
        self.log(self._DEBUG, f"Query sent to {self.editor}")
        if response_impala['status'] != 0:
            self.log(self._WARNING, f"There was an error in the query: {response_impala['message']}",
                     show_notification=True)
            return None
        # print(response)

        # update mydata with the changes from response_impala
        notebook['id'] = response_impala['history_id']
        notebook['uuid'] = response_impala['history_uuid']
        snippet['result']['handle'] = response_impala['handle']
        snippet['status'] = "running"
        # Reduced versions
        result['handle'] = response_impala['handle']
        result['type'] = "table"
        data = {
            'notebook': {"id": notebook['id'],
                         "uuid": notebook['uuid'],
                         "isSaved": false, "sessions": [self.session],
                         "type": "query-" + self.editor_type, "name": ""},
            'snippet': {"id": snippet['id'], "type": self.editor_type, "status": "running",
                        "statementType": "text", "statement": snippet['statement'],
                        "aceCursorPosition": {"row": 0, "column": 11},
                        "statementPath": "", "associatedDocumentUuid": null,
                        "properties": {"settings": []},
                        "result": result,
                        "database": snippet['database'], "compute": self.impala['computes'][0],
                        "wasBatchExecuted": false}

        }
        return data

    def _get_result_pandas(self, payload_data: dict) -> pd.DataFrame | None:
        """Downloads a statement and returns it as a pandas dataframe"""
        if not payload_data:
            self.log(self._INFO, "Nothing to download. Check previous call to execute_impala for errors")
            return
        self.log(self._DEBUG, "Checking status")
        check_status = self.ajax(self._endpoint_check_status, payload=format_payload(**payload_data))
        self.log(self._DEBUG, f"Status: {check_status}")
        has_more = True
        all_data = []
        columns = []
        while has_more:
            data_payload = format_payload(notebook=payload_data['notebook'], snippet=payload_data['snippet'],
                                          rows=10000)
            data = self.ajax(self._endpoint_fetch_data, payload=data_payload)
            columns = [meta['name'] for meta in data['result']['meta']]
            all_data.extend(data['result']['data'])
            has_more = data['result']['has_more']
            # print(len(all_data))
        df = pd.DataFrame(all_data, columns=columns)
        return df

    def _download_result(self, payload_data: dict, filename: str, file_format="csv", append=False) -> str | None:
        """
        Downloads result of an impala query to the given file in the given format (defaults to csv)
        :param payload_data: result of execute_impala
        :param filename: name of the filename (without extension) to create
        :param file_format: csv (default) or xls
        :param append: True to append to data to the file, False to overwrite file
        :return: the name of the downloaded file or None if nothing could be downloaded
        """
        if not payload_data:
            self.log(self._INFO, "Nothing to download. Check previous call to execute_impala for errors")
            return
        self.log(self._DEBUG, "Reading csrfmiddlewaretoken from notebook")
        notebook_id = payload_data['notebook']['id']
        editor = self._request(self._endpoint_editor, params=dict(editor=notebook_id))
        csrfmiddlewaretoken = get_csfrmiddlewaretoken(editor)
        self.log(self._DEBUG, "Csrfmiddlewaretoken read")
        headers = {"Referer": editor.url}
        headers.update(self.headers)
        self.log(self._INFO, "Starting download")
        download = self._request(self._endpoint_download, headers=headers,
                                 payload=format_payload(csrfmiddlewaretoken=csrfmiddlewaretoken,
                                                        notebook=payload_data['notebook'],
                                                        snippet=payload_data['snippet'],
                                                        format=file_format, ),
                                 stream=True)
        if download.status_code == 200:
            check_content_type(download, filename)
            downloaded_header = False
            total_size_in_bytes = int(download.headers.get('content-length', 0))
            progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True)
            with open(filename, "wb" if not append else "ab") as f:
                for data in download.iter_content(self.content_chunk_size):
                    progress_bar.update(len(data))
                    if append and not downloaded_header:
                        new_content = remove_header(data)
                        downloaded_header = new_content is not None
                        data = new_content
                    f.write(data)
            progress_bar.close()
            return filename
        else:
            return

    def get_row_number(self, query: str) -> int | None:
        """Gets the number of rows of a certain query. Returns None on any error"""
        row_query = f"with t as ( {query} ) select count(*) from t"
        if self.editor == "hive":
            row_query += " limit 1"     # it does not work without it
        res = self.execute_query(row_query, format="pandas", log_query=False)
        if res is not None and not res.empty:
            return res.iat[0, 0]
        else:
            return None

    @handle_exceptions
    def execute_query(self, query: str, database: str = None, path: str = None, name: str = None,
                      format: str = "csv", chunk_rows: int = None, log_query=True,
                      variables: dict = None) -> \
            (pd.DataFrame | str | None):
        """
        Executes a query and downloads it to a file. For large queries, csv format is the fasted, followed by xls and
        pandas is muuuuuuch slower. For shorter queries (1.000 rows or fewer), it can be worth to use pandas format
        :param query: the sql statement
        :param database: a scheme/database to use as reference. None to use the last available
        :param path: Directory where file would be saved. If None (default) current folder will be used
        :param name: name of the file to create without extension. If None (default) no file will be saved
        :param format: either csv, xls (to save as .xlsx) or pandas (does not save a file and returns result as pandas)
        :param chunk_rows: an integer to split query into subqueries of the given number of rows. Only for csv format
        :param log_query: True to log the query, False (default) otherwise
        :param variables: dict of variables to pass to impala. Variable names are the keys of the dict
        :return: a pandas DataFrame with the query or None if a file was created
        """
        query = add_variables(query, variables)
        if log_query:
            self.log(self._INFO, f"Executing query: {query}")
        retval = True
        filename = get_filename(path, name, format)
        is_csv = format.lower() == "csv"
        # Only CSV can be chunked
        chunk_rows = chunk_rows if is_csv else None
        if chunk_rows:
            rows = self.get_row_number(query)
            if rows is None:
                self.log(self._DEBUG, "There was an error in the query. See previous logs")
                return
        else:
            rows = None
        order_by = "1"  # default value: order by first column
        if rows and self.editor == "hive":
            # Order by 1 does not work in hive with select *.
            # Then we have to sort by the first column...which is? As no idea, do an easy query
            df = self.execute_query(query + " limit 1", format="pandas")
            order_by = df.columns[0]
            pass
        queries = get_query_chunked(query, total_size=rows, chunk_size=chunk_rows, order_by=order_by)
        for idx_statement, statement in enumerate(queries):
            if chunk_rows:
                self.log(self._INFO, f"Downloading chunk {idx_statement + 1}/{len(queries)}")
            impala_res = self._execute_impala(database or self.default_db, statement)
            if impala_res is None:
                self.log(self._INFO, "Nothing to download. Check previous call to execute_impala for errors")
                return
            if format.lower() in ("csv", "xls"):
                append = True if chunk_rows is not None and idx_statement > 0 else False
                retval = self._download_result(impala_res, filename, file_format=format, append=append)
            elif format in ("pandas",):
                result = self._get_result_pandas(impala_res)
                if filename is not None and result is not None:
                    result.to_excel(filename)
                    retval = filename
                else:
                    return result
        if retval:
            self.log(self._INFO, f"Data downloaded into file: {retval}", show_notification=retval)
        else:
            self.log(self._INFO, f"Could not download any file for {query}, review logs",
                     show_notification=True)
        return retval

    def filebrowser(self, path: str, filter: str = None) -> dict:
        """Gets a dictionary {name: path} with the list of contents of a given path, optionally
        returning files that contain a certain pattern"""

        ok = is_hdfs_s3(path)       # Will raise exception if fails
        retval = dict()
        has_more_pages = True
        page_num = 1
        while has_more_pages:
            params = {
                'format': 'json',
                'sortby': 'name',
                'descending': 'false',
                'pagesize': '1000',
                'pagenum': str(page_num),
                '_': str(timestamp()),
            }
            if filter:
                params['filter'] = filter
            res = self.ajax(self._endpoint_filebrowser_view + "=" + urllib.parse.quote(path), params=params)
            retval = {}
            for file in res['files']:
                retval[file['name']] = file['path']
            page_num += 1
            has_more_pages = res['page']['num_pages'] > page_num
        return retval

    def download_file(self, hdfs_file_path: str, path: str = None, local_filename: str = None) -> str:
        """
        Downloads a file from hdfs and stores it in the given folder. Optionally name can be forced
        :param hdfs_file_path: the absolute hdfs file path to be downloaded
        :param path: local folder where file would be stored. Defaults to current path
        :param local_filename: name (with extension) of the file to be created. Defaults to the file to be downloaded
        :return: the name of the created file
        """
        self.log(self._INFO, f"Starting download of remote file {hdfs_file_path}")
        response = self._request(self._endpoint_filebrowser_download + "=" + urllib.parse.quote(hdfs_file_path),
                                 stream=True)
        filename = local_filename or hdfs_file_path.split("/")[-1]
        local_filename = os.path.join(path or os.getcwd(), filename)
        total_size_in_bytes = int(response.headers.get('content-length', 0))
        progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True)
        with open(local_filename, 'wb') as file:
            for data in response.iter_content(self.content_chunk_size):
                progress_bar.update(len(data))
                file.write(data)
        progress_bar.close()
        self.log(self._INFO, f"File {local_filename} downloaded", show_notification=local_filename)
        return local_filename


if __name__ == '__main__':
    pass
    # KeyringStorage().delete(all=True)
    # hue.log("info", "Process finished")
    hue = Hue()
