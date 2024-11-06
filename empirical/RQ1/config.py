import platform

version = "3.1.0"  # for use in IoTcube.
pf = platform.platform()
if "Windows" in pf:  # Windows
    gitBinary = r"D:\Program Files\Git\bin\git.exe"
    diffBinary = r"D:\Program Files\Git\usr\bin\diff.exe"
else:  # POSIX
    gitBinary = "git"
    diffBinary = "diff"
    javaBinary = "java"

CTAGS_PATH = "/path/to/ctags"
joern_path = "/path/to/joern"
