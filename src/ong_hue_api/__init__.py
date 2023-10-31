import platform

name = platform.node()
# Text JSON data includes these elements, this is direct translation to python
null, true, false = None, True, False

is_windows = platform.system() == "Windows"
is_macos = platform.system() == "Darwin"
