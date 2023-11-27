"""
Functions to manage sensible information (username, password, session id...)
Includes a tkinter dialog to change hue server and password
"""
from __future__ import annotations

import os
import pickle
import time
import urllib.parse
from tkinter import *
from tkinter import messagebox
from tkinter.simpledialog import Dialog

import keyring
import requests

from ong_hue_api import name, is_windows
if is_windows:
    import win32security

from ong_hue_api.logs import create_logger


def check_server(server: str) -> str | None:
    """Gets server address and returns it properly formatted or None if it is invalid"""
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


class KeyringStorage:
    """Module to deal with username, passwords, etc., stored in computer keyring"""

    # Encoding used for binary pickle to work
    PICKLE_ENCODING = 'ISO-8859-1'

    def __init__(self, logger=None, check=True, username: str = None):
        """
        Inits the keyring wrapper.
        :param logger: a logger instance (or creates a new one)
        :param check: True to check if server address is valid, and also if username and password are
        :param username: optional name (to override default login username)
        """
        self.name = name
        self.logger = logger or create_logger()
        self.__username = None
        default_user = self.username
        self.is_logged_in_username = username is None or username == default_user
        if not self.is_logged_in_username:
            self.__username = username
        self.__domain = None if self.is_logged_in_username else ""
        if check:
            self.check_and_ask()

    def check_and_ask(self, password: str = None):
        """Checks if server/password are valid. If not, a dialog appears for asking for username and password"""
        if not self.check(password):
            retval = ConfigDialog(self).result
            if retval is None:
                self.logger.error("HUE server or password are invalid. Exiting...")
                exit(-1)
            else:
                server, password = retval
                self.set_hue_server(server)
                self.set_password(password)

    @property
    def username(self):
        """Username, read from USERNAME environ variable"""
        if not self.__username:
            self.__username = os.environ.get('USERNAME', os.environ.get("USER"))
        return self.__username

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

    def check(self, password: str = None, server: str = None) -> bool:
        """
        Checks if server and username/password are valid.
        :param password: a given password (that will be stored in the keyring if valid) or None to use the stored one.
        If username is the current logged-in username, the password is checked against Windows credentials. Otherwise,
        password is not validated and returns True if password is a not empty/None value
        :param server: a server address (or None to use the stored one)
        :return: True if both server and password are valid, False otherwise
        """
        test_server = server or self.hue_server
        self.logger.debug(f"Checking hue server: {test_server}")
        server = check_server(server) or self.hue_server
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
                if is_windows:
                    hUser = win32security.LogonUser(
                        self.username,
                        self.domain,
                        password,
                        # win32security.LOGON32_LOGON_NETWORK,
                        win32security.LOGON32_LOGON_INTERACTIVE,
                        win32security.LOGON32_PROVIDER_DEFAULT
                    )
                else:
                    return True     # Not windows...password is assumed to be valid
            except Exception as e:
                self.logger.error(e.strerror)
                return False
            else:
                self.logger.debug("Password OK")
                return True

    @property
    def password(self) -> str:
        """Gets password from keyring. If not password is found in keyring, a loging screen is shown for the user"""
        password = keyring.get_password(self.key_password, self.username)
        return password

    def set_password(self, password: str):
        """Shows a password screen for the user to enter a new password and stores it in the keyring"""
        keyring.set_password(self.key_password, self.username, password)

    def set_cookies(self, session):
        """Stores all cookies from given session in the keyring"""
        self.__write_dict(self.key_cookies, session.cookies)

    def delete(self, cookies: bool = False, hue_server: bool = False, password: bool = False, all: bool = False):
        """
        Deletes from keyring cookies, hue_server and password or all
        :param cookies: flag to delete cookies info, defaults to False
        :param hue_server:  flag to delete hue_server info, defaults to False
        :param password:  flag to delete password info, defaults to False
        :param all:  flag to delete all info, defaults to False. If True overrides the rest of flags, if False this flag
        is ignored and individual flags prevail
        :return: None
        """
        # Delete all information about the session (cookies, impala instance, notebook...)
        if cookies or all:
            try:
                keyring.delete_password(self.key_cookies, self.username)
                keyring.delete_password(self.key_impala_session_notebook, self.username)
                keyring.delete_password(self.key_databases, self.username)
            except:
                pass
        if hue_server or all:
            try:
                keyring.delete_password(self.key_server, self.username)
            except:
                pass
        if password or all:
            try:
                keyring.delete_password(self.key_password, self.username)
            except:
                pass

    def __write_dict(self, key: str, input_dict: dict):
        """Writes given dict to the given key in the keyring"""
        value = pickle.dumps(input_dict)
        if not is_windows:
            value = urllib.parse.quote(value.decode(self.PICKLE_ENCODING))
        else:
            value = value.decode(self.PICKLE_ENCODING)
        keyring.set_password(key, self.username, value)
        value2 = keyring.get_password(key, self.username)
        assert value2 == value, "Dictionary was not properly stored in keyring"

    def __read_dict(self, key: str) -> dict:
        """Reads a dict pickled in the storage"""
        value = keyring.get_password(key, self.username)
        if is_windows:
            retval = pickle.loads(value.encode(self.PICKLE_ENCODING)) if value is not None else dict()
        else:
            retval = pickle.loads(urllib.parse.unquote(value).encode(self.PICKLE_ENCODING))
        return retval

    def get_cookies(self) -> dict:
        """Returns a dict of cookies from the keyring storage"""
        cookies = self.__read_dict(self.key_cookies)
        expired = any(c.expires < time.time() if c.expires else False for c in cookies)
        if expired:
            return dict()       # Empty dict, cookies are expired
        else:
            return cookies

    @property
    def hue_server(self):
        """Returns server address from the keyring storage"""
        server = check_server(keyring.get_password(self.key_server, self.username))
        return server

    def set_hue_server(self, server: str):
        """Stores server address in the keyring storage"""
        keyring.set_password(self.key_server, self.username, check_server(server))

    @property
    def impala_session_notebook(self) -> dict | None:
        return self.__read_dict(self.key_impala_session_notebook)

    def set_impala_session_notebook(self, impala, session, notebook):
        input_dict = dict(impala=impala, session=session, notebook=notebook)
        self.__write_dict(self.key_impala_session_notebook, input_dict)

    @property
    def databases(self) -> list | None:
        return self.__read_dict(self.key_databases).get("databases")

    def set_databases(self, databases):
        input_dict = dict(databases=databases)
        self.__write_dict(self.key_databases, input_dict)


class ConfigDialog(Dialog):

    def __init__(self, keyring: KeyringStorage, username: str = None):
        title = "Api de Hue"
        self.keyring = keyring
        self.hue_server = keyring.hue_server
        self.password = keyring.password
        default_username = ((self.keyring.domain + "\\") if self.keyring.domain else "") + self.keyring.username
        self.username = username or default_username
        parent = Tk()
        parent.withdraw()
        Dialog.__init__(self, parent=parent, title=title)

    def getresult(self):
        return self.entry_server.get(), self.entry_password.get()

    def destroy(self):
        self.entry_server = None
        self.entry_password = None
        Dialog.destroy(self)

    def body(self, master):
        # self.geometry("300x180")
        self.geometry("350x200")    # Make it a bit bigger so it can be better seen in macos
        padx = 5
        pady = 2

        row = 0
        w = Label(master, text="Configuracion del acceso a HUE", justify=CENTER)
        w.grid(row=row, padx=padx, pady=pady * 2, sticky=W)
        row += 1
        w = Label(master, text="Url de HUE (copiarla del navegador):", justify=LEFT)
        w.grid(row=row, padx=padx, pady=pady, sticky=W)
        row += 1
        self.entry_server = Entry(master, width=150, name="server")
        self.entry_server.grid(row=row, padx=padx, pady=pady, sticky=W + E)
        row += 1
        w = Label(master, text=f"Password para {self.username}: ", justify=LEFT)
        w.grid(row=row, padx=padx, pady=pady, sticky=W)
        row += 1
        self.entry_password = Entry(master, width=150, name="password", show="*")
        self.entry_password.grid(row=row, padx=padx, pady=pady, sticky=W + E)
        row += 1
        for widget, value in [(self.entry_server, self.hue_server), (self.entry_password, self.password)]:
            if value:
                widget.insert(0, value)
                # self.entry.select_range(0, END)
        return self.entry_password  # <- This will receive focus

    def validate(self):
        try:
            server, password = retval = self.getresult()
        except ValueError:
            messagebox.showwarning(
                "Illegal value",
                self.errormessage + "\nPlease try again",
                parent=self
            )
            return 0
        if not check_server(server):
            messagebox.showwarning(
                "Error: " + self.title(),
                "El nombre del servidor no es correcto" + "\nInténtelo de nuevo",
                parent=self
            )
            return 0
        if not self.keyring.check(password, server):
            messagebox.showwarning(
                "Error: " + self.title(),
                "La contraseña no es válida." + "\nInténtelo de nuevo",
                parent=self
            )
            return 0
        self.result = retval
        return 1


def delete_all():
    """Deletes all keyring values for current logged-in user and for demo user"""
    for username in (None, "demo"):
        info = KeyringStorage(create_logger(), username=username, check=False)
        info.delete(all=True)


if __name__ == '__main__':


    # delete_all()
    # exit(0)

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
