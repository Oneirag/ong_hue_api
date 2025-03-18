"""
Functions to manage sensible information (username, password, session id...)
Includes a tkinter dialog to change hue server and password
"""
from __future__ import annotations

import os
import platform
import urllib.parse

import requests
import requests.cookies
from ong_utils import InternalStorage, get_current_domain, get_current_user

from ong_utils.ui import UiField, simple_dialog
from ong_utils.credentials import verify_credentials

from ong_hue_api.logs import create_logger


def check_server(server: str, **kwargs) -> str | None:
    """Gets server address and returns it properly formatted or None if it is invalid"""
    print(f"Checking server {server}")
    if not server:
        return None
    res = urllib.parse.urlparse(server, scheme='', allow_fragments=True)
    if res.scheme not in ("http", "https"):
        return None
    hue_server = res._replace(path="", params="", query="", fragment="").geturl()
    # Checks url if it can be reached and responds as if where hue
    try:
        res = requests.get(hue_server, allow_redirects=False)
        if res.status_code == 302 and res.headers.get("Location") == "/hue/accounts/login?next=/":
            return hue_server
        else:
            return None
    except Exception as e:
        print(e)
        return None


def hue_config_dialog(default_password: str = "", default_hue_server: str = "",
                      default_user: str = "",
                      use_system_credentials: bool = True) -> dict:
    field_list = [UiField(name="domain",  # Key of the dict in the return dictionary and for validation functions
                          label="Domain",  # Name to the shown for the user
                          default_value=get_current_domain() if use_system_credentials else "",  # Default value to be used
                          editable=False,  # Not editable
                          ),
                  UiField(name="username", label="User",
                          default_value=get_current_user() if use_system_credentials else default_user or "",
                          editable=not use_system_credentials,        # Allow editing user if is not system user
                          ),
                  UiField(name="password", label="Password", default_value=default_password or "",
                          show="*",  # Hides password by replacing with *
                          validation_func=verify_credentials if use_system_credentials else None,
                          # The validation function receives values of all fields, so should accept extra **kwargs
                          ),
                  UiField(name="server", label="Hue server",
                          default_value=default_hue_server or "",
                          validation_func=check_server,
                          width=40      # Make this field longer
                          )]
    # Call the function to open the login window with custom options
    res = simple_dialog(title="Hue api", description="Parameters needed to log in to hue",
                        field_list=field_list)
    return res


class KeyringStorage:
    """Module to deal with username, passwords, etc., stored in computer keyring"""

    def __init__(self, logger=None, check=True, username: str = None, use_system_credentials: bool = True):
        """
        Init the keyring wrapper.
        :param logger: a logger instance (or creates a new one)
        :param check: True to check if server address is valid, and also if username and password are
        :param username: optional name (to override default login username)
        :param use_system_credentials: True to use current system login user and verify system credentials. False to
        avoid system credential check and allow for user to be modified
        """
        self.__valid_server = None      # A Cache to avoid checking server
        self.use_system_credentials = use_system_credentials
        self.name = platform.node()                # Current computer name
        self.logger = logger or create_logger()
        self.__username = None
        self.current_logged_user = get_current_user()
        self.is_logged_in_username = username is None or username == self.current_logged_user
        if not self.is_logged_in_username:
            self.__username = username
        self.__domain = None if self.is_logged_in_username else ""
        if check:
            self.check_and_ask()

    def check_and_ask(self, password: str = None):
        """Checks if server/password are valid. If not, a dialog appears for asking for username and password"""
        if not self.check(password):
            retval = hue_config_dialog(default_password=password, default_hue_server=self.hue_server,
                                       default_user=self.username,
                                       use_system_credentials=self.use_system_credentials)
            if not retval:
                self.logger.error("HUE server or password are invalid. Exiting...")
                exit(-1)
            else:
                server, password = retval['server'], retval['password']
                self.set_hue_server(server)
                self.set_password(password)
                if not self.use_system_credentials:
                    self.set_username(retval['username'])

    @property
    def username(self):
        """Username, read from USERNAME environ variable if use_system_credentials, else read from keyring"""
        if not self.__username:
            if self.use_system_credentials:
                self.__username = get_current_user()
            else:
                self.__username = self.__get_value(self.key_username)
        return self.__username

    def set_username(self, username: str):
        self.__set_value(self.key_username, username)
        self.__username = username

    @property
    def domain(self):
        """Domain, read from USERDOMAIN environ variable"""
        if self.__domain is None:
            self.__domain = os.environ.get('USERDOMAIN')
        return self.__domain

    @property
    def key_cookies(self):
        """Returns the key in the keyring used to store cookies"""
        return f"{self.name}:cookies"

    @property
    def key_server(self):
        """Returns the key in the keyring used to store server address"""
        return f"{self.name}:server"

    @property
    def key_password(self):
        """Returns the key in the keyring used to store server address"""
        return f"{self.name}:password"

    @property
    def key_impala_session_notebook(self):
        return f"{self.name}:impala_session_notebook"

    @property
    def key_databases(self):
        return f"{self.name}:databases"

    @property
    def key_username(self):
        return f"{self.name}:username"

    def check(self, password: str = None, server: str = None) -> bool:
        """
        Checks if server and username/password are valid.
        :param password: a given password (that will be stored in the keyring if valid) or None to use the stored one.
        If username is the current logged-in username, the password is checked against Windows credentials. Otherwise,
        password is not validated and returns True if password is a not empty/None value
        :param server: a server address (or None to use the stored one)
        :return: True if both server and password are valid, False otherwise
        """
        server = server or self.hue_server
        if server is not None and server != self.__valid_server:
            self.logger.debug(f"Checking hue server: {server}")
            server = check_server(server) or self.hue_server
            self.__valid_server = server
        if server is None:
            self.logger.debug("Server value is not valid")
            return False
        else:
            self.logger.debug(f"Server valid: {server}")
            self.set_hue_server(server)
        password = password or self.password
        if not self.is_logged_in_username:
            # If username is not the already logged-in user, it cannot be validated against windows credentials
            # It will only check that password is a valid string
            if password:
                self.set_password(password)
                return True
            else:
                return False
        else:
            try:
                self.logger.debug(f"Checking password of {self.domain}\\{self.username}")
                if verify_credentials(self.username, self.domain, password) or not self.use_system_credentials:
                    if password:
                        self.logger.debug("Password OK")
                        return True
                    else:
                         return False
                else:
                    return False
            except Exception as e:
                self.logger.error(e.strerror)
                return False

    def __get_value(self, key: str):
        return InternalStorage(key).get_value(self.current_logged_user)

    def __set_value(self, key: str, value):
        return InternalStorage(key).store_value(self.current_logged_user, value)

    @property
    def password(self) -> str:
        """Gets password from keyring. If not password is found in keyring, a loging screen is shown for the user"""
        return self.__get_value(self.key_password)

    def set_password(self, password: str):
        """Shows a password screen for the user to enter a new password and stores it in the keyring"""
        self.__set_value(self.key_password, password)

    def set_cookies(self, session):
        """Stores all cookies from given session in the keyring"""
        cookies = session.cookies
        cookie_dict = [dict(name=c.name, value=c.value, domain=c.domain, path=c.path, expires=c.expires)
                       for c in cookies]
        self.__set_value(self.key_cookies, cookie_dict)

    def get_cookies(self) -> list:
        """Returns a list of cookies from the keyring storage"""
        cookies_dict = self.__get_value(self.key_cookies)
        if not cookies_dict:
            return list()
        cookies = [requests.cookies.create_cookie(**c) for c in cookies_dict]
        expired = any(c.is_expired() for c in cookies)
        if expired:
            return list()       # Empty dict, cookies are expired
        else:
            return cookies

    @classmethod
    def delete(cls, cookies: bool = False, hue_server: bool = False, password: bool = False, all: bool = False):
        """
        Deletes from keyring cookies, hue_server and password or all
        :param cookies: flag to delete cookies info, defaults to False
        :param hue_server:  flag to delete hue_server info, defaults to False
        :param password:  flag to delete password and username info, defaults to False
        :param all:  flag to delete all info, defaults to False. If True overrides the rest of flags, if False this flag
        is ignored and individual flags prevail
        :return: None
        """
        # Delete all information about the session (cookies, impala instance, notebook...)
        keys_to_delete = []
        self = KeyringStorage(use_system_credentials=False, check=False)     # Avoid asking for credentials
        if cookies or all:
            keys_to_delete.append(self.key_cookies)
            keys_to_delete.append(self.key_impala_session_notebook)
            keys_to_delete.append(self.key_databases)
        if hue_server or all:
            keys_to_delete.append(self.key_server)
        if password or all:
            keys_to_delete.append(self.key_password)
            keys_to_delete.append(self.key_username)

        for delete_key in keys_to_delete:
            try:
                InternalStorage(delete_key).remove_stored_value(get_current_user())
                self.logger.debug(f"Deleted key: {delete_key}")
            except Exception as e:
                self.logger.error(f"Could not delete {delete_key}: {e}")

    @property
    def hue_server(self):
        """Returns server address from the keyring storage"""
        stored_server = self.__get_value(self.key_server)
        if stored_server is not None and stored_server == self.__valid_server:
            return stored_server
        else:
            server = check_server(self.__get_value(self.key_server))
            self.__valid_server = server
            return server

    def set_hue_server(self, server: str):
        """Stores server address in the keyring storage"""
        self.__set_value(self.key_server, server)

    @property
    def impala_session_notebook(self) -> dict | None:
        return self.__get_value(self.key_impala_session_notebook)

    def set_impala_session_notebook(self, impala, session, notebook):
        input_dict = dict(impala=impala, session=session, notebook=notebook)
        self.__set_value(self.key_impala_session_notebook, input_dict)

    @property
    def databases(self) -> list | None:
        return self.__get_value(self.key_databases)

    def set_databases(self, databases):
        self.__set_value(self.key_databases, databases)


def delete_all():
    """Deletes all keyring values for current logged-in user and for demo user"""
    for username in (None, "demo"):
        info = KeyringStorage(create_logger(), username=username, check=False)
        info.delete(all=True)


if __name__ == '__main__':


#    delete_all()
#    exit(0)

    info = KeyringStorage(create_logger())

    info.delete(cookies=True)

    # info.delete(all=True)
    server = info.hue_server
    print(f"Hue server: {server}")
    print("Hello {domain}\\{user}, your password is {password}".format(domain=info.domain, user=info.username,
                                                                       password=info.password))
    if info.check():
        print("Your password is valid")
    else:
        print("Invalid password")
