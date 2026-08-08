"""
CLI-friendly entry point for HueRest.

This module is a thin convenience wrapper that pre-configures HueRest with
UIMode.CLI: credentials are read from stdin (via getpass), errors are reported
through the configured logger, and exceptions are raised as HueRestError
instead of opening a tkinter dialog or calling exit().

Equivalent to:

    from ong_hue_api.hue_rest_api import HueRest, UIMode
    hue = HueRest(ui=UIMode.CLI)
"""

from ong_hue_api.hue_rest_api import HueRest, HueRestError, UIMode


class HueRestCli(HueRest):
    """HueRest configured to interact with the user through the CLI
    (stdin/logger/raised exceptions) instead of the default GUI dialogs.

    Public API is identical to HueRest; only the user interaction differs.
    """

    def __init__(self):
        super().__init__(ui=UIMode.CLI)


__all__ = ["HueRestCli", "HueRestError", "UIMode"]
