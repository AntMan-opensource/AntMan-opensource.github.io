import os
import platform
import re
import subprocess
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from ast_parser import ASTParser


def get_platform():
    global osName
    global bits

    pf = platform.platform()
    bits, _ = platform.architecture()
    if "Windows" in pf:
        osName = "win"
        bits = ""
    elif "Linux" in pf:
        osName = "linux"
        if "64" in bits:
            bits = "64"
        else:
            bits = "86"
    else:
        osName = "osx"
        bits = ""


def setEnvironment(caller):
    get_platform()
    global javaCallCommand
    if caller == "GUI":
        cwd = os.getcwd()
        if osName == "win":
            javaCallCommand = os.path.join(cwd, "FuncParser-opt.exe ")

        elif osName == "linux" or osName == "osx":
            javaCallCommand = '"{0}" -Xmx1024m -jar "{1}" '.format(
                config.javaBinary, os.path.join(cwd, "FuncParser-opt.jar")
            )

    else:
        if osName == "win":
            base_path = os.path.dirname(os.path.abspath(__file__))
            javaCallCommand = os.path.join(base_path, "FuncParser-opt.exe ")
        elif osName == "linux" or osName == "osx":
            base_path = os.path.dirname(os.path.abspath(__file__))
            javaCallCommand = '"{0}" -Xmx1024m -jar "{1}" '.format(
                config.javaBinary, os.path.join(base_path, "FuncParser-opt.jar")
            )


class function:
    parentFile = None
    parentNumLoc = None
    name = None
    lines = None
    funcId = None
    parameterList = []
    variableList = []
    dataTypeList = []
    funcCalleeList = []
    funcBody = None

    def __init__(self, fileName):
        self.parentFile = fileName
        self.parameterList = []
        self.variableList = []
        self.dataTypeList = []
        self.funcCalleeList = []

    def removeListDup(self):
        self.parameterList = list(set(self.parameterList))
        self.variableList = list(set(self.variableList))
        self.dataTypeList = list(set(self.dataTypeList))
        self.funcCalleeList = list(set(self.funcCalleeList))


def loadSource(rootDirectory):
    maxFileSizeInBytes = None
    maxFileSizeInBytes = 2097152
    walkList = os.walk(rootDirectory)
    srcFileList = []
    for path, dirs, files in walkList:
        if "codeclone" in path:
            continue
        for fileName in files:
            ext = fileName.lower()
            if ext.endswith(".java"):
                absPathWithFileName = path.replace("\\", "/") + "/" + fileName
                if os.path.islink(absPathWithFileName):
                    continue
                if maxFileSizeInBytes is not None:
                    if os.path.getsize(absPathWithFileName) < maxFileSizeInBytes:
                        srcFileList.append(absPathWithFileName)
                else:
                    srcFileList.append(absPathWithFileName)
    return srcFileList


def loadVul(rootDirectory):
    maxFileSizeInBytes = None
    walkList = os.walk(rootDirectory)
    srcFileList = []
    for path, dirs, files in walkList:
        for fileName in files:
            if fileName.endswith("OLD.vul"):
                absPathWithFileName = path.replace("\\", "/") + "/" + fileName
                if maxFileSizeInBytes is not None:
                    if os.path.getsize(absPathWithFileName) < maxFileSizeInBytes:
                        srcFileList.append(absPathWithFileName)
                else:
                    srcFileList.append(absPathWithFileName)
    return srcFileList


def removeComment(string):
    c_regex = re.compile(
        r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE,
    )
    return "".join(
        [
            c.group("noncomment")
            for c in c_regex.finditer(string)
            if c.group("noncomment")
        ]
    )


def normalize(string):
    return "".join(
        string.replace("\n", "")
        .replace("\r", "")
        .replace("\t", "")
        .replace("{", "")
        .replace("}", "")
        .split(" ")
    ).lower()


def abstract(instance, level):
    originalFunctionBody = instance.funcBody
    originalFunctionBody = removeComment(originalFunctionBody)
    if int(level) >= 0:
        abstractBody = originalFunctionBody

    if int(level) >= 1:
        parameterList = instance.parameterList
        for param in parameterList:
            if len(param) == 0:
                continue
            try:
                paramPattern = re.compile("(^|\W)" + param + "(\W)")
                abstractBody = paramPattern.sub("\g<1>FPARAM\g<2>", abstractBody)
            except:
                pass

    if int(level) >= 2:
        dataTypeList = instance.dataTypeList
        for dtype in dataTypeList:
            if len(dtype) == 0:
                continue
            try:
                dtypePattern = re.compile("(^|\W)" + dtype + "(\W)")
                abstractBody = dtypePattern.sub("\g<1>DTYPE\g<2>", abstractBody)
            except:
                pass

    if int(level) >= 3:
        variableList = instance.variableList
        for lvar in variableList:
            if len(lvar) == 0:
                continue
            try:
                lvarPattern = re.compile("(^|\W)" + lvar + "(\W)")
                abstractBody = lvarPattern.sub("\g<1>LVAR\g<2>", abstractBody)
            except:
                pass

    if int(level) >= 4:
        funcCalleeList = instance.funcCalleeList
        for fcall in funcCalleeList:
            if len(fcall) == 0:
                continue
            try:
                fcallPattern = re.compile("(^|\W)" + fcall + "(\W)")
                abstractBody = fcallPattern.sub("\g<1>FUNCCALL\g<2>", abstractBody)
            except:
                pass

    parser = ASTParser(originalFunctionBody, "newc")
    nodes = parser.query_all("(string_literal)@name")
    for node in nodes:
        try:
            abstractBody = abstractBody.replace(node.text.decode(), "STRING")
        except:
            pass
    return (originalFunctionBody, abstractBody)


delimiter = "\r\0?\r?\0\r"


def parseFile_shallow(srcFileName, caller):
    global javaCallCommand
    global delimiter
    setEnvironment(caller)
    javaCallCommand += '"' + srcFileName + '" 0'
    print(javaCallCommand)
    functionInstanceList = []
    try:
        astString = subprocess.check_output(
            javaCallCommand, stderr=subprocess.STDOUT, shell=True
        )
    except subprocess.CalledProcessError as e:
        print("Parser Error:", e)
        astString = ""
    funcList = astString.split(delimiter)
    for func in funcList[1:]:
        functionInstance = function(srcFileName)
        elemsList = func.split("\n")[1:-1]
        if len(elemsList) > 9:
            functionInstance.parentNumLoc = int(elemsList[1])
            functionInstance.name = elemsList[2]
            functionInstance.lines = (
                int(elemsList[3].split("\t")[0]),
                int(elemsList[3].split("\t")[1]),
            )
            functionInstance.funcId = int(elemsList[4])
            functionInstance.funcBody = "\n".join(elemsList[9:])
            functionInstanceList.append(functionInstance)

    return functionInstanceList


def parseFile_deep(srcFileName, caller):
    global javaCallCommand
    global delimiter
    setEnvironment(caller)
    javaCallCommand += '"' + srcFileName + '" 1'
    functionInstanceList = []

    try:
        astString = subprocess.check_output(
            javaCallCommand, stderr=subprocess.STDOUT, shell=True
        ).decode()
    except subprocess.CalledProcessError as e:
        print("Parser Error:", e)
        astString = ""
    funcList = astString.split(delimiter)
    for func in funcList[1:]:
        functionInstance = function(srcFileName)

        elemsList = func.split("\n")[1:-1]
        if len(elemsList) > 9:
            functionInstance.parentNumLoc = int(elemsList[1])
            functionInstance.name = elemsList[2]
            functionInstance.lines = (
                int(elemsList[3].split("\t")[0]),
                int(elemsList[3].split("\t")[1]),
            )
            functionInstance.funcId = int(elemsList[4])
            functionInstance.parameterList = elemsList[5].rstrip().split("\t")
            functionInstance.variableList = elemsList[6].rstrip().split("\t")
            functionInstance.dataTypeList = elemsList[7].rstrip().split("\t")
            functionInstance.funcCalleeList = elemsList[8].rstrip().split("\t")
            functionInstance.funcBody = "\n".join(elemsList[9:])
            functionInstanceList.append(functionInstance)

    return functionInstanceList
