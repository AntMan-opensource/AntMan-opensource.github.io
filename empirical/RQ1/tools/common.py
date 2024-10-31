from enum import Enum


class Mode(Enum):
    CVE = "cve"
    PATCH = "patch"


class Language(Enum):
    JAVA = "javasrc"
    C = "newc"


class HunkType(Enum):
    ADD = "add"
    DEL = "del"
    MOD = "mod"