"""Tests for the CLI mode of HueRest.

These tests do NOT require a hue server. They exercise the new code paths
introduced for the CLI UI: tkinter imports are deferred, building
HueRestCli() works with a stubbed credentials manager, and errors are
raised as HueRestError instead of calling exit() or opening a GUI.
"""

from __future__ import annotations

import ast
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure HUE_REST_API_SERVER is set before HueRest's class body runs.
os.environ.setdefault("HUE_REST_API_SERVER", "http://stub-hue-server/")

import pandas as pd


class _StubCredentialsManager:
    """Stand-in for ong_hue_api.hue_rest_api.CredentialsManager that
    never touches the system keyring and never persists state.

    Behaves like a freshly-created credentials manager: nothing stored,
    so HueRest will go through the standard login (username/password)
    branch, which our test patches via the CliUi.prompt_credentials.
    """

    def __init__(self, ui=None, *, preloaded_password: str | None = "stub-pw"):
        self.ui = ui
        self.username = "stub-user"
        # When preloaded_password is set, get_user_password returns it
        # without ever calling the ui (this avoids accidentally opening a
        # tkinter dialog in the GUI-mode test).
        self.password = preloaded_password
        self.token = None
        self.refresh_token = None
        self.cookies = None
        self.storage = MagicMock()
        self.storage.store_value = MagicMock()
        self.storage.remove_stored_value = MagicMock()

    def store_token_cookies(self, token, refresh_token, cookies):
        self.token = token
        self.refresh_token = refresh_token
        self.cookies = cookies

    def get_user_password(self):
        if self.password is not None:
            return self.username, self.password
        username, password = self.ui.prompt_credentials(self.username)
        self.username = username
        self.password = password
        return username, password

    def clean_stored_password(self):
        self.token = None
        self.refresh_token = None
        self.cookies = None
        self.password = None


def _patched_post_side_effect(
    *,
    query_status: int = 0,
    query_message: str = "",
    history_uuid: str = "uuid-1",
    rows: int = 2,
):
    """Returns a side_effect function for `requests.post` that covers the
    endpoints HueRest calls in __init__ + execute_query."""

    def side_effect(url, data=None, **kwargs):
        resp = MagicMock()
        resp.cookies.get_dict.return_value = {}
        if url.endswith("/api/v1/token/verify/"):
            resp.status_code = 200
            resp.json.return_value = {}
        elif url.endswith("/api/v1/token/refresh/"):
            resp.status_code = 200
            resp.json.return_value = {"access": "stub-access"}
        elif url.endswith("/api/v1/token/auth"):
            resp.status_code = 200
            resp.json.return_value = {
                "access": "stub-access",
                "refresh": "stub-refresh",
            }
        elif url.endswith("/api/v1/editor/execute/impala"):
            resp.status_code = 200
            resp.json.return_value = {
                "status": query_status,
                "history_uuid": history_uuid,
                "message": query_message,
            }
        elif url.endswith("/api/v1/editor/check_status"):
            resp.status_code = 200
            resp.json.return_value = {"query_status": {"status": "available"}}
        elif url.endswith("/api/v1/editor/fetch_result_data"):
            resp.status_code = 200
            resp.json.return_value = {
                "result": {
                    "meta": [{"name": "a"}, {"name": "b"}],
                    "data": [[i, "x"] for i in range(rows)],
                    "has_more": False,
                }
            }
        else:
            resp.status_code = 200
            resp.json.return_value = {}
        return resp

    return side_effect


class TestCliModeImport(unittest.TestCase):
    """Source-level checks: HueRest's module file must not have a top-level
    `import tkinter` statement (it was previously a hard import, which broke
    the module on headless boxes)."""

    def test_hue_rest_api_source_has_no_top_level_tkinter_import(self):
        import ong_hue_api.hue_rest_api as mod

        with open(mod.__file__, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        offending = []
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "tkinter" or alias.name.startswith("tkinter."):
                        offending.append((node.lineno, f"import {alias.name}"))
            elif isinstance(node, ast.ImportFrom):
                mod_name = node.module or ""
                if mod_name == "tkinter" or mod_name.startswith("tkinter."):
                    offending.append((node.lineno, f"from {mod_name} import ..."))
        self.assertEqual(
            offending,
            [],
            f"tkinter must be imported lazily, but found top-level: {offending}",
        )

    def test_hue_rest_api_cli_source_has_no_tkinter_import(self):
        import ong_hue_api.hue_rest_api_cli as mod

        with open(mod.__file__, "r", encoding="utf-8") as f:
            source = f.read()
        self.assertNotIn("import tkinter", source)
        self.assertNotIn("from tkinter", source)

    def test_cli_ui_does_not_import_tkinter_on_construction(self):
        """The _CliUi class is the only one that should be usable on a
        headless box. The only thing we can verify here is that it does
        not have a hard dependency on tkinter (the GUI ui does, lazily)."""
        from ong_hue_api.hue_rest_api import _CliUi, _GuiUi

        # _CliUi source must not reference tkinter at all
        import ong_hue_api.hue_rest_api as mod

        cls_src = mod.__file__
        with open(cls_src, "r", encoding="utf-8") as f:
            source = f.read()
        # Find the _CliUi class block in the source
        idx = source.find("class _CliUi")
        end = source.find("\nclass ", idx + 1)
        block = source[idx:end] if end > 0 else source[idx:]
        self.assertNotIn("tkinter", block, "_CliUi must not reference tkinter")
        # And it must not subclass anything that needs tkinter
        self.assertNotIn("(_tk.Tk", block)

    def test_gui_ui_does_lazy_tkinter_import(self):
        """_GuiUi must import tkinter lazily, inside its methods, not at
        construction. This is what makes the module importable headlessly."""
        import ast
        import ong_hue_api.hue_rest_api as mod

        with open(mod.__file__, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        # Find the _GuiUi class node
        gui_class = None
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "_GuiUi":
                gui_class = node
                break
        self.assertIsNotNone(gui_class, "_GuiUi class not found")
        # Any `import tkinter` inside _GuiUi must be inside a function/method,
        # not at class body level.
        for sub in gui_class.body:
            if isinstance(sub, (ast.Import, ast.ImportFrom)):
                modname = (
                    sub.module if isinstance(sub, ast.ImportFrom) else None
                ) or ""
                names = (
                    [a.name for a in sub.names]
                    if isinstance(sub, ast.Import)
                    else [modname]
                )
                if any(n == "tkinter" or n.startswith("tkinter.") for n in names):
                    self.fail(
                        f"_GuiUi must import tkinter lazily, found top-level: "
                        f"line {sub.lineno}"
                    )


class TestHueRestCliConstruction(unittest.TestCase):
    """HueRestCli uses CLI ui and reads credentials from stdin via the ui."""

    def _build(
        self,
        *,
        query_status: int = 0,
        query_message: str = "",
        history_uuid: str = "uuid-1",
        rows: int = 2,
        post_side_effect=None,
        run_query: bool = True,
    ):
        """Build a HueRestCli and optionally run a query inside the patch
        context. Returns (instance, mock_post). If `run_query` is False, the
        caller is responsible for using the returned instance within an
        active patch (call site must re-enter the same mocks)."""
        from ong_hue_api.hue_rest_api_cli import HueRestCli
        from ong_hue_api import hue_rest_api

        if post_side_effect is None:
            post_side_effect = _patched_post_side_effect(
                query_status=query_status,
                query_message=query_message,
                history_uuid=history_uuid,
                rows=rows,
            )
        # `session = requests.Session()` is bound at class body, so the actual
        # `post` call goes through HueRest.session.post (an instance method).
        # We must patch requests.Session.post, not the module-level requests.post.
        ctx = (
            patch.object(hue_rest_api, "CredentialsManager", _StubCredentialsManager),
            patch("ong_hue_api.hue_rest_api.getpass"),
            patch("builtins.input", return_value=""),
            patch("requests.Session.post"),
        )
        with ctx[0], ctx[1] as mock_getpass, ctx[2], ctx[3] as mock_post:
            mock_getpass.getpass.return_value = "stub-pw"
            mock_post.side_effect = post_side_effect
            instance = HueRestCli()
            if run_query:
                instance._last_query_df = instance.execute_query(
                    "select 1", raise_exception_on_error=True
                )
        return instance, mock_post

    def test_uses_cli_ui(self):
        instance, _ = self._build(run_query=False)
        from ong_hue_api.hue_rest_api import _CliUi

        self.assertIsInstance(instance._ui, _CliUi)

    def test_execute_query_returns_dataframe(self):
        instance, _ = self._build(rows=3)
        df = instance._last_query_df
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(list(df.columns), ["a", "b"])
        self.assertEqual(len(df), 3)


class TestHueRestCliErrorRaises(unittest.TestCase):
    """When something goes wrong in CLI mode, HueRestError must be raised
    (not exit())."""

    def test_query_failure_raises(self):
        from ong_hue_api.hue_rest_api_cli import HueRestCli
        from ong_hue_api import hue_rest_api
        from ong_hue_api.hue_rest_api import HueRestError

        with patch.object(
            hue_rest_api, "CredentialsManager", _StubCredentialsManager
        ), patch("ong_hue_api.hue_rest_api.getpass") as mock_getpass, patch(
            "builtins.input", return_value=""
        ), patch("requests.Session.post") as mock_post:
            mock_getpass.getpass.return_value = "stub-pw"
            mock_post.side_effect = _patched_post_side_effect(
                query_status=1, query_message="syntax error near 'foo'"
            )
            instance = HueRestCli()
            with self.assertRaises(HueRestError) as ctx:
                instance.execute_query("select foo", raise_exception_on_error=True)
            self.assertIn("syntax error", str(ctx.exception))

    def test_cli_does_not_call_exit(self):
        """In CLI mode, bad credentials must raise HueRestError, not exit()."""
        from ong_hue_api.hue_rest_api_cli import HueRestCli
        from ong_hue_api import hue_rest_api
        from ong_hue_api.hue_rest_api import HueRestError

        def bad_creds_side_effect(url, data=None, **kwargs):
            resp = MagicMock()
            resp.cookies.get_dict.return_value = {}
            if url.endswith("/api/v1/token/verify/"):
                resp.status_code = 200
                resp.json.return_value = {}
            elif url.endswith("/api/v1/token/refresh/"):
                resp.status_code = 200
                resp.json.return_value = {"access": "stub-access"}
            elif url.endswith("/api/v1/token/auth"):
                resp.status_code = 401
                resp.json.return_value = {"detail": "bad creds"}
            else:
                resp.status_code = 200
                resp.json.return_value = {}
            return resp

        with patch.object(
            hue_rest_api, "CredentialsManager", _StubCredentialsManager
        ), patch("ong_hue_api.hue_rest_api.getpass") as mock_getpass, patch(
            "builtins.input", return_value=""
        ), patch("requests.Session.post") as mock_post, patch(
            "ong_hue_api.hue_rest_api.exit"
        ) as mock_exit:
            mock_getpass.getpass.return_value = "stub-pw"
            mock_post.side_effect = bad_creds_side_effect
            with self.assertRaises(HueRestError):
                HueRestCli()
            mock_exit.assert_not_called()


class TestHueRestGuiModeStillWorks(unittest.TestCase):
    """The default (GUI) mode must still construct without error and have
    a _GuiUi instance."""

    def test_gui_ui_default(self):
        from ong_hue_api.hue_rest_api import HueRest, UIMode, _GuiUi
        from ong_hue_api import hue_rest_api

        with patch.object(
            hue_rest_api, "CredentialsManager", _StubCredentialsManager
        ), patch("ong_hue_api.hue_rest_api.getpass") as mock_getpass, patch(
            "builtins.input", return_value=""
        ), patch("requests.Session.post") as mock_post:
            mock_getpass.getpass.return_value = "stub-pw"
            mock_post.side_effect = _patched_post_side_effect()
            # The _GuiUi.prompt_credentials will be called, but never actually
            # executed because CredentialsManager is stubbed: it doesn't even
            # call get_user_password (token/refresh return success).
            instance = HueRest()
            self.assertIsInstance(instance._ui, _GuiUi)
            self.assertEqual(instance._ui_mode, UIMode.GUI)

    def test_explicit_cli_mode_on_huerest(self):
        """HueRest(ui=UIMode.CLI) should behave like HueRestCli."""
        from ong_hue_api.hue_rest_api import HueRest, UIMode, _CliUi
        from ong_hue_api import hue_rest_api

        with patch.object(
            hue_rest_api, "CredentialsManager", _StubCredentialsManager
        ), patch("ong_hue_api.hue_rest_api.getpass") as mock_getpass, patch(
            "builtins.input", return_value=""
        ), patch("requests.Session.post") as mock_post:
            mock_getpass.getpass.return_value = "stub-pw"
            mock_post.side_effect = _patched_post_side_effect()
            instance = HueRest(ui=UIMode.CLI)
            self.assertIsInstance(instance._ui, _CliUi)
            self.assertEqual(instance._ui_mode, UIMode.CLI)


if __name__ == "__main__":
    unittest.main()
