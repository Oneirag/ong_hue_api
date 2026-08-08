import platform

name = platform.node()

# Text JSON data includes these elements, this is direct translation to python
null, true, false = None, True, False

from ong_hue_api.hue_rest_api import HueRest, HueRestError, UIMode
from ong_hue_api.hue_rest_api_cli import HueRestCli

__all__ = ["HueRest", "HueRestCli", "HueRestError", "UIMode"]
