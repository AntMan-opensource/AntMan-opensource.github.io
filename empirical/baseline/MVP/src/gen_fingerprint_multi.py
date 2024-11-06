import copy
import functools
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import traceback
import xml.dom.minidom
from datetime import datetime
from multiprocessing import Pool
from queue import Queue
from xml.dom import minidom
from xml.dom.minidom import parse

import cpu_heater
import joern_session
import numpy as np
import pandas as pd
from tqdm import tqdm

encoding_format = "ISO-8859-1"
JOERN_PATH = "/path/to/joern/joern-cli"
originalDir = os.path.dirname(os.path.abspath(__file__))


def set_joern_env(joern_path: str):
    os.environ["PATH"] = joern_path + os.pathsep + os.environ["PATH"]
    assert (
        subprocess.run(["which", "joern"], stdout=subprocess.PIPE)
        .stdout.decode()
        .strip()
        == joern_path + "/joern"
    )
    os.environ["JOERN_HOME"] = joern_path


def readCommit(CVE_ID, location, git_repo_location, work_dir, sess):
    worker_id = sess.worker_id.replace("/", "_")
    method_info = []
    hash = location.split("/")[-1].replace("commit-", "").replace(".txt", "")
    with open(location, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        files = []
        file_seperator = []
        for i in range(len(lines)):
            if lines[i].startswith("diff --git"):
                file_seperator.append(i)
        for i in range(len(file_seperator) - 1):
            files.append(lines[file_seperator[i] : file_seperator[i + 1] - 1])
        files.append(lines[file_seperator[len(file_seperator) - 1] : len(lines)])
    for file in files:
        parseFile(CVE_ID, file, method_info, git_repo_location, work_dir, hash, sess)
    os.chdir(work_dir)
    with open(f"metadata/method_info_{worker_id}.json", "w") as f:
        json.dump(method_info, f)


def parseFile(CVE_ID, file, method_info, git_repo_location, work_dir, hash, sess):
    worker_id = sess.worker_id.replace("/", "_")
    extension = ["c", "cpp", "c++", "C", "cc", "cxx", "h"]
    info = {}
    info["oldFileName"] = file[0].split(" ")[2]
    info["newFileName"] = file[0].split(" ")[3][:-1]
    if (
        info["oldFileName"].split(".")[-1] not in extension
        or info["newFileName"].split(".")[-1] not in extension
    ):
        return
    if (
        "test" in info["oldFileName"]
        or "test" in info["newFileName"]
        or "tst" in info["oldFileName"]
        or "tst" in info["newFileName"]
    ):
        return
    flag_old = True
    flag_new = True
    if file[1].startswith("old mode"):
        info["oldCommit"] = file[3].split(" ")[1].split("..")[0].replace("\n", "")
        info["newCommit"] = file[3].split(" ")[1].split("..")[1].replace("\n", "")
    elif file[1].startswith("new file mode"):
        info["oldCommit"] = file[2].split(" ")[1].split("..")[0].replace("\n", "")
        info["newCommit"] = file[2].split(" ")[1].split("..")[1].replace("\n", "")
        flag_old = False
    elif file[1].startswith("similarity index"):
        return
    elif file[1].startswith("deleted file mode"):
        info["oldCommit"] = file[2].split(" ")[1].split("..")[0].replace("\n", "")
        info["newCommit"] = file[2].split(" ")[1].split("..")[1].replace("\n", "")
        flag_new = False
    else:
        info["oldCommit"] = file[1].split(" ")[1].split("..")[0]
        info["newCommit"] = file[1].split(" ")[1].split("..")[1]
    old_name = info["oldCommit"] + "-" + info["oldFileName"].split("/")[-1]
    new_name = info["newCommit"] + "-" + info["newFileName"].split("/")[-1]
    if "00000000" in info["oldCommit"]:
        flag_old = False
    elif "00000000" in info["newCommit"]:
        flag_new = False
    info["add"] = []
    info["delete"] = []
    os.chdir(git_repo_location)
    if not flag_old:
        os.system(
            "git show "
            + info["newCommit"]
            + " > "
            + work_dir
            + "temp_"
            + worker_id
            + "/"
            + new_name
        )
        format_and_del_comment(work_dir + "temp_" + worker_id + "/" + new_name)
    elif not flag_new:
        if not os.path.exists(work_dir + "vulFile/" + CVE_ID):
            os.system("mkdir -pv " + work_dir + "vulFile/" + CVE_ID)
        os.system(
            "git show "
            + info["oldCommit"]
            + " > "
            + work_dir
            + "vulFile/"
            + CVE_ID
            + "/"
            + old_name
        )
        os.system(
            "git show "
            + info["oldCommit"]
            + " > "
            + work_dir
            + "temp_"
            + worker_id
            + "/"
            + old_name
        )
        format_and_del_comment(work_dir + "temp_" + worker_id + "/" + old_name)
        format_and_del_comment(work_dir + "vulFile/" + CVE_ID + "/" + old_name)
    else:
        if not os.path.exists(work_dir + "vulFile/" + CVE_ID):
            os.system("mkdir -pv " + work_dir + "vulFile/" + CVE_ID)
        os.system(
            "git show "
            + info["oldCommit"]
            + " > "
            + work_dir
            + "vulFile/"
            + CVE_ID
            + "/"
            + old_name
        )
        os.system(
            "git show "
            + info["oldCommit"]
            + " > "
            + work_dir
            + "temp_"
            + worker_id
            + "/"
            + old_name
        )
        os.system(
            "git show "
            + info["newCommit"]
            + " > "
            + work_dir
            + "temp_"
            + worker_id
            + "/"
            + new_name
        )
        format_and_del_comment(work_dir + "temp_" + worker_id + "/" + old_name)
        format_and_del_comment(work_dir + "vulFile/" + CVE_ID + "/" + old_name)
        format_and_del_comment(work_dir + "temp_" + worker_id + "/" + new_name)
    os.system(
        "git diff -w "
        + work_dir
        + "temp_"
        + worker_id
        + "/"
        + old_name
        + " "
        + work_dir
        + "temp_"
        + worker_id
        + "/"
        + new_name
        + " > "
        + work_dir
        + "temp_"
        + worker_id
        + "/"
        + info["oldCommit"]
        + "__split__"
        + new_name
    )
    with open(
        work_dir
        + "temp_"
        + worker_id
        + "/"
        + info["oldCommit"]
        + "__split__"
        + new_name,
        "r",
    ) as f:
        file = f.readlines()
    add_line = 0
    delete_line = 0
    flag1 = True
    flag2 = True
    for line in file:
        try:
            if line.startswith("@@"):
                delete_line = int(line.split("-")[1].split(",")[0]) - 1
                add_line = int(line.split("+")[1].split(",")[0]) - 1
            elif line.startswith("+") and not line.startswith("+++"):
                if not line.strip() == "+":
                    flag1 = False
                add_line += 1
                info["add"].append(add_line)
            elif line.startswith("-") and not line.startswith("---"):
                if not line.strip() == "-":
                    flag2 = False
                delete_line += 1
                info["delete"].append(delete_line)
            else:
                add_line += 1
                delete_line += 1
        except Exception as e:
            print(e)
            return
    if flag1 and flag2:
        return
    change_dict = {}
    change_dict["oldMethod"] = {}
    change_dict["newMethod"] = {}
    os.chdir(work_dir)

    sess.import_code(work_dir + "temp_" + worker_id + "/" + old_name)
    sess.run_script("metadata", params={"cveid": str(worker_id)})
    method_list = []
    with open(f"./metadata/method_{worker_id}.json") as f:
        json_obj = json.load(f)
        for obj in json_obj:
            if "lineNumber" in obj.keys() and obj["fullName"] != ":<global>":
                if obj["lineNumber"] == obj["lineNumberEnd"]:
                    continue
                method_dict = {}
                method_dict["name"] = obj["signature"]
                method_dict["lineStart"] = obj["lineNumber"]
                method_dict["lineEnd"] = obj["lineNumberEnd"]
                method_list.append(method_dict)
                with open(
                    work_dir + "temp_" + worker_id + "/" + old_name,
                    "r",
                    encoding=encoding_format,
                ) as fp:
                    old_content = fp.readlines()
                if method_dict["lineStart"] in info["delete"]:
                    for i in range(
                        method_dict["lineStart"], method_dict["lineEnd"] + 1
                    ):
                        if i not in info["delete"]:
                            i_content = (
                                old_content[i - 1]
                                .replace(" ", "")
                                .replace("{", "")
                                .replace("}", "")
                                .replace("\t", "")
                                .replace("\n", "")
                                .replace("(", "")
                                .replace(")", "")
                            )
                            if i_content != "":
                                change_dict["oldMethod"][method_dict["name"]] = i
                                break
    delete_dict = {}
    for line in info["delete"]:
        for method in method_list:
            if method["lineStart"] <= line <= method["lineEnd"]:
                if method["name"] not in delete_dict.keys():
                    delete_dict[method["name"]] = [
                        method["lineStart"],
                        method["lineEnd"],
                    ]
                delete_dict[method["name"]].append(line)
    this_method_info_dict = {}
    this_method_info_dict["oldFile"] = old_name
    this_method_info_dict["deleteMethod"] = delete_dict
    os.system(f"rm metadata/method_{worker_id}.json")
    sess.import_code(work_dir + "temp_" + worker_id + "/" + new_name)
    sess.run_script("metadata", params={"cveid": str(worker_id)})
    method_list = []
    with open(f"./metadata/method_{worker_id}.json") as f:
        json_obj = json.load(f)
        for obj in json_obj:
            if "lineNumber" in obj.keys() and obj["fullName"] != ":<global>":
                if obj["lineNumber"] == obj["lineNumberEnd"]:
                    continue
                method_dict = {}
                method_dict["name"] = obj["signature"]
                method_dict["lineStart"] = obj["lineNumber"]
                method_dict["lineEnd"] = obj["lineNumberEnd"]
                method_list.append(method_dict)
                with open(
                    work_dir + "temp_" + worker_id + "/" + new_name,
                    "r",
                    encoding=encoding_format,
                ) as fp:
                    new_content = fp.readlines()
                if method_dict["lineStart"] in info["add"]:
                    for i in range(
                        method_dict["lineStart"], method_dict["lineEnd"] + 1
                    ):
                        if i not in info["add"]:
                            i_content = (
                                new_content[i - 1]
                                .replace(" ", "")
                                .replace("{", "")
                                .replace("}", "")
                                .replace("\t", "")
                                .replace("\n", "")
                                .replace("(", "")
                                .replace(")", "")
                            )
                            if i_content != "":
                                change_dict["newMethod"][method_dict["name"]] = i
                                break
    add_dict = {}
    for line in info["add"]:
        for method in method_list:
            if method["lineStart"] <= line <= method["lineEnd"]:
                if method["name"] not in add_dict.keys():
                    add_dict[method["name"]] = [method["lineStart"], method["lineEnd"]]
                add_dict[method["name"]].append(line)
    this_method_info_dict["newFile"] = new_name
    this_method_info_dict["addMethod"] = add_dict
    this_method_info_dict["delete"] = info["delete"]
    this_method_info_dict["add"] = info["add"]
    new_old_map = {}
    old_new_map = {}
    delete_lines = info["delete"]
    add_lines = info["add"]
    delete = 1
    add = 1
    for i in range(1, 100000):
        while delete in delete_lines:
            delete += 1
        while add in add_lines:
            add += 1
        old_new_map[delete] = add
        new_old_map[add] = delete
        delete += 1
        add += 1
    change_method_map_dict = {}
    for key in change_dict["oldMethod"].keys():
        if key in this_method_info_dict["addMethod"]:
            continue
        for key1 in change_dict["newMethod"].keys():
            if (
                old_new_map[change_dict["oldMethod"][key]]
                == change_dict["newMethod"][key1]
            ):
                change_method_map_dict[key] = key1
    this_method_info_dict["change_method_map"] = change_method_map_dict
    for method in this_method_info_dict["addMethod"].keys():
        if method not in this_method_info_dict["deleteMethod"].keys():
            if this_method_info_dict["addMethod"][method][0] not in new_old_map.keys():
                if method in change_method_map_dict.values():
                    del this_method_info_dict["addMethod"][method][1:3]
                    continue
                if "pureAddMethod" not in this_method_info_dict.keys():
                    this_method_info_dict["pureAddMethod"] = []
                this_method_info_dict["pureAddMethod"].append(
                    {
                        method: [
                            this_method_info_dict["addMethod"][method][0],
                            this_method_info_dict["addMethod"][method][1],
                        ]
                    }
                )
                pass
            else:
                this_method_info_dict["deleteMethod"][method] = [
                    new_old_map[this_method_info_dict["addMethod"][method][0]]
                ]
        elif len(this_method_info_dict["addMethod"][method]) != 1:
            del this_method_info_dict["addMethod"][method][1]
    for method in this_method_info_dict["deleteMethod"].keys():
        if method not in this_method_info_dict["addMethod"].keys():
            if (
                this_method_info_dict["deleteMethod"][method][0]
                not in old_new_map.keys()
            ):
                if method in change_method_map_dict.keys():
                    del this_method_info_dict["deleteMethod"][method][1:3]
                    continue
                if "pureDeleteMethod" not in this_method_info_dict.keys():
                    this_method_info_dict["pureDeleteMethod"] = []
                this_method_info_dict["pureDeleteMethod"].append(
                    {
                        method: [
                            this_method_info_dict["deleteMethod"][method][0],
                            this_method_info_dict["deleteMethod"][method][1],
                        ]
                    }
                )
            else:
                this_method_info_dict["addMethod"][method] = [
                    old_new_map[this_method_info_dict["deleteMethod"][method][0]]
                ]
        elif len(this_method_info_dict["deleteMethod"][method]) != 1:
            del this_method_info_dict["deleteMethod"][method][1]
    os.system(f"rm metadata/method_{worker_id}.json")
    method_info.append(this_method_info_dict)


def parse(file_location, worker_id):
    CONST_DICT = {"FP": "FPARAM", "LV": "LVAR", "DT": "DTYPE", "FC": "FUNCCALL"}
    FP_coor_list = []
    LV_coor_list = []
    DT_coor_list = []
    FC_coor_list = []
    with open(f"metadata/FP_{worker_id}.json", "r", encoding="utf8") as f:
        FP_coor_list = json.load(f)
    with open(f"metadata/newLV_{worker_id}.json", "r", encoding="utf8") as f:
        LV_coor_list = json.load(f)
    with open(f"metadata/DT_{worker_id}.json", "r", encoding="utf8") as f:
        DT_coor_list = json.load(f)
    with open(f"metadata/FC_{worker_id}.json", "r", encoding="utf8") as f:
        FC_coor_list = json.load(f)
    with open(f"metadata/STRING_{worker_id}.json", "r", encoding="utf8") as f:
        STRING_coor_list = json.load(f)
    change_dict = {}
    for FP in FP_coor_list:
        if FP["_2"] not in change_dict.keys():
            change_dict[FP["_2"]] = {}
        change_dict[FP["_2"]][FP["_3"]] = {}
        change_dict[FP["_2"]][FP["_3"]]["type"] = "FP"
        change_dict[FP["_2"]][FP["_3"]]["code"] = FP["_1"]
    for LV in LV_coor_list:
        if LV["_1"] == "NULL":
            continue
        if LV["_2"] not in change_dict.keys():
            change_dict[LV["_2"]] = {}
        change_dict[LV["_2"]][LV["_3"]] = {}
        change_dict[LV["_2"]][LV["_3"]]["type"] = "LV"
        change_dict[LV["_2"]][LV["_3"]]["code"] = LV["_1"]
    for DT in DT_coor_list:
        if "*" in DT["_1"] and "[" in DT["_1"]:
            continue
        if DT["_4"] not in change_dict.keys():
            change_dict[DT["_4"]] = {}
        code = DT["_1"]
        typeFullName = DT["_3"]
        DT_dup = False
        for col in change_dict[DT["_4"]].keys():
            if change_dict[DT["_4"]][col]["type"] == "DT":
                if change_dict[DT["_4"]][col]["typeFullName"] == typeFullName:
                    DT_dup = True
                    break
        if DT_dup:
            continue
        pointer_cnt = 0
        for char in code:
            if char == "*":
                pointer_cnt += 1
        if pointer_cnt != 0:
            delete_col = []
            for col in change_dict[DT["_4"]].keys():
                if change_dict[DT["_4"]][col]["type"] == "LV":
                    delete_col.append(col)
            for col in delete_col:
                change_dict[DT["_4"]][col + 1] = change_dict[DT["_4"]][col]
                change_dict[DT["_4"]].pop(col)
        name = DT["_2"]
        pos = DT["_5"]
        if pointer_cnt != 0:
            pos += 1
        index = code.rfind(name)
        index = pos - index
        change_dict[DT["_4"]][index] = {}
        change_dict[DT["_4"]][index]["pos"] = pos
        change_dict[DT["_4"]][index]["type"] = "DT"
        change_dict[DT["_4"]][index]["code"] = DT["_1"]
        change_dict[DT["_4"]][index]["name"] = DT["_2"]
        change_dict[DT["_4"]][index]["typeFullName"] = DT["_3"]
        change_dict[DT["_4"]][index]["pointerCnt"] = pointer_cnt
    for FC in FC_coor_list:
        if FC["_2"] not in change_dict.keys():
            change_dict[FC["_2"]] = {}
        change_dict[FC["_2"]][FC["_3"]] = {}
        change_dict[FC["_2"]][FC["_3"]]["type"] = "FC"
        change_dict[FC["_2"]][FC["_3"]]["code"] = FC["_1"]
    for STRING in STRING_coor_list:
        if STRING["_2"] not in change_dict.keys():
            change_dict[STRING["_2"]] = {}
        change_dict[STRING["_2"]][STRING["_3"]] = {}
        change_dict[STRING["_2"]][STRING["_3"]]["type"] = "STRING"
        change_dict[STRING["_2"]][STRING["_3"]]["code"] = STRING["_1"]
        fmt_pattern = r"%[\\.]*[0-9]*[.\-*#]*[0-9]*[hljztL]*[diuoxXfFeEgGaAcCsSpnm]"
        fmt_list = re.findall(fmt_pattern, STRING["_1"][1:-1])
        if len(fmt_list) != 0:
            write_code = "".join(fmt_list)
            write_code = '"' + write_code + '"'
            change_dict[STRING["_2"]][STRING["_3"]]["write"] = write_code
        else:
            change_dict[STRING["_2"]][STRING["_3"]]["write"] = "STRING"
    with open(file_location, "r", encoding=encoding_format) as f:
        fp = f.readlines()
        for line_number in change_dict:
            change_dict[line_number] = sorted(change_dict[line_number].items())
            line = fp[line_number - 1]
            write_line = ""
            length = len(change_dict[line_number])
            for i in range(length):
                column_number = change_dict[line_number][i][0]
                if i != length - 1:
                    column_number_next = change_dict[line_number][i + 1][0]
                element_dict = change_dict[line_number][i][1]
                change_type = element_dict["type"]
                if i == 0:
                    if change_type != "DT":
                        write_line += line[: column_number - 1]
                        if change_type != "STRING":
                            write_line += CONST_DICT[change_type]
                        else:
                            write_line += element_dict["write"]
                        if i != length - 1:
                            write_line += line[
                                column_number
                                - 1
                                + len(element_dict["code"]) : column_number_next - 1
                            ]
                        else:
                            write_line += line[
                                column_number - 1 + len(element_dict["code"]) :
                            ]
                    else:
                        write_line += line[: column_number - 1]
                        write_line += CONST_DICT[change_type]
                        if i != length - 1:
                            write_line += line[
                                element_dict["pos"]
                                - 2
                                - element_dict["pointerCnt"] : column_number_next - 1
                            ]
                        else:
                            write_line += line[
                                column_number - 1 + len(element_dict["name"]) :
                            ]
                elif i == length - 1:
                    if change_type != "DT":
                        if change_type != "STRING":
                            write_line += CONST_DICT[change_type]
                        else:
                            write_line += element_dict["write"]
                        write_line += line[
                            column_number - 1 + len(element_dict["code"]) :
                        ]
                    else:
                        write_line += CONST_DICT[change_type]
                        write_line += line[
                            column_number - 1 + len(element_dict["name"]) :
                        ]
                else:
                    if change_type != "DT":
                        if change_type != "STRING":
                            write_line += CONST_DICT[change_type]
                        else:
                            write_line += element_dict["write"]
                        if i != length - 1:
                            write_line += line[
                                column_number
                                - 1
                                + len(element_dict["code"]) : column_number_next - 1
                            ]
                        else:
                            write_line += line[
                                column_number - 1 + len(element_dict["code"]) :
                            ]
                    else:
                        write_line += CONST_DICT[change_type]
                        if i != length - 1:
                            write_line += line[
                                column_number
                                - 1
                                + len(element_dict["name"]) : column_number_next - 1
                            ]
                        else:
                            write_line += line[
                                column_number - 1 + len(element_dict["name"]) :
                            ]
            if write_line[-1] != "\n":
                write_line += "\n"
            fp[line_number - 1] = write_line
    with open(file_location, "w", encoding=encoding_format) as f:
        f.writelines(fp)


def slicing(file_name, method_name, sess):
    print(os.getcwd())
    worker_id = sess.worker_id.replace("/", "_")
    print(file_name)
    os.chdir(originalDir)
    with open(f"metadata/method_info_{worker_id}.json", "r") as f:
        json_object = json.load(f)
        for pair in json_object:
            if file_name.split("/")[-1] == pair["oldFile"]:
                lineStart = pair["deleteMethod"][method_name][0]
                break
            elif file_name.split("/")[-1] == pair["newFile"]:
                lineStart = pair["addMethod"][method_name][0]

    sess.import_code(file_name)
    sess.run_script("slice", params={"line": lineStart, "cveid": str(worker_id)})

    file_name = file_name.split("/")[-1]
    label_line_map = {}
    cdg_map = {}
    ddg_map = {}
    slicing_set = set()
    with open(f"metadata/PDG_{worker_id}.json", "r", encoding="utf8") as f:
        json_object = json.load(f)
        if len(json_object) == 0:
            return cdg_map, ddg_map, slicing_set
        list1 = json_object[0].split("\n")
        for line in list1:
            if not line.startswith("digraph"):
                if line.startswith('"'):
                    num_end = line.find('"', 1)
                    label_number = int(line[1:num_end])
                    line_number_start = line.find("<SUB>")
                    line_number_end = line.find("</SUB>")
                    if line_number_start == -1 or line_number_end == -1:
                        continue
                    line_number = int(line[line_number_start + 5 : line_number_end])
                    label_line_map[label_number] = line_number
                elif len(line) > 1:
                    from_end = line.find('"', 3)
                    from_label = int(line[3:from_end])
                    to_start = line.find('"', from_end + 1)
                    to_end = line.find('"', to_start + 1)
                    to_label = int(line[to_start + 1 : to_end])
                    label_start = line.find('[ label = "')
                    label = line[label_start + 11 : -3]
                    if (
                        from_label not in label_line_map.keys()
                        or to_label not in label_line_map.keys()
                    ):
                        continue
                    if label_line_map[from_label] != label_line_map[to_label]:
                        if label.startswith("CDG"):
                            if label_line_map[from_label] not in cdg_map.keys():
                                cdg_map[label_line_map[from_label]] = set()
                            cdg_map[label_line_map[from_label]].add(
                                label_line_map[to_label]
                            )
                        else:
                            if label_line_map[from_label] not in ddg_map.keys():
                                ddg_map[label_line_map[from_label]] = set()
                            ddg_map[label_line_map[from_label]].add(
                                label_line_map[to_label]
                            )
    assignment_set = set()
    with open(f"metadata/assignment_{worker_id}.json", "r", encoding="utf8") as f:
        list1 = json.load(f)
        for line in list1:
            assignment_set.add(line)
    return_set = set()
    with open(f"metadata/return_{worker_id}.json", "r", encoding="utf8") as f:
        list1 = json.load(f)
        for line in list1:
            return_set.add(line)
    control_set = set()
    with open(f"metadata/control_{worker_id}.json", "r", encoding="utf8") as f:
        list1 = json.load(f)
        for line in list1:
            control_set.add(line)
    criterion_set = set()
    with open(f"metadata/method_info_{worker_id}.json", "r", encoding="utf8") as f:
        json_object = json.load(f)
        for pair in json_object:
            if file_name == pair["oldFile"]:
                criterion_set = set(pair["deleteMethod"][method_name][1:])
                break
            elif file_name == pair["newFile"]:
                criterion_set = set(pair["addMethod"][method_name][1:])
    slicing_set.update(criterion_set)
    print(slicing_set)
    for line in criterion_set:
        for key in cdg_map.keys():
            if line in cdg_map[key]:
                slicing_set.add(key)
        for key in ddg_map.keys():
            if line in ddg_map[key]:
                slicing_set.add(key)

        if line in assignment_set:
            if line in cdg_map.keys():
                for l in cdg_map[line]:
                    slicing_set.add(l)
            if line in ddg_map.keys():
                for l in ddg_map[line]:
                    slicing_set.add(l)

        elif line in control_set:
            temp_criterion_set = set()
            res = set()
            for key in ddg_map.keys():
                if line in ddg_map[key]:
                    temp_criterion_set.add(key)
            for cri in temp_criterion_set:
                if cri in ddg_map.keys():
                    for l in ddg_map[cri]:
                        res.add(l)
            if len(res) == 0:
                if line in cdg_map.keys():
                    for l in cdg_map[line]:
                        slicing_set.add(l)
            else:
                for l in res:
                    slicing_set.add(l)

        elif line in return_set:
            pass
        else:
            temp_criterion_set = set()
            res = set()
            for key in ddg_map.keys():
                if line in ddg_map[key]:
                    temp_criterion_set.add(key)
            for cri in temp_criterion_set:
                if cri in ddg_map.keys():
                    for l in ddg_map[cri]:
                        res.add(l)
            for l in res:
                slicing_set.add(l)
    return cdg_map, ddg_map, slicing_set


def entropy_selection(
    vul_syn,
    add_line,
    delete_line,
    indirect_vul_syn,
    old_file,
    old_new_map,
    new_slicing_set,
    worker_id,
):
    entropy = 0
    threshold = 5
    stmt_list = []
    with open(
        "./temp_" + worker_id + "/" + old_file, "r", encoding=encoding_format
    ) as f:
        lines = f.readlines()
    for line in vul_syn:
        stmt_list.append(
            lines[line - 1]
            .replace(" ", "")
            .replace("{", "")
            .replace("}", "")
            .replace("\t", "")
            .replace("\n", "")
            .replace("(", "")
            .replace(")", "")
        )
    temp_set = set(stmt_list)
    entropy = len(temp_set)
    print(indirect_vul_syn)
    while entropy > threshold and len(indirect_vul_syn) != 0:
        stmt = 0
        max_dis = 0
        for indirect in indirect_vul_syn:
            new_line = old_new_map[indirect]
            old_x = -1
            new_x = -1
            if len(delete_line) != 0:
                old_x = min(delete_line, key=lambda x: abs(x - indirect))
            if len(add_line) != 0:
                new_x = min(add_line, key=lambda x: abs(x - new_line))
            temp_dis = -1
            if old_x == -1:
                temp_dis = abs(new_x - new_line)
            elif new_x == -1:
                temp_dis = abs(old_x - indirect)
            else:
                temp_dis = min(abs(old_x - indirect), abs(new_x - new_line))
            if temp_dis > max_dis:
                max_dis = temp_dis
                stmt = indirect
        stmt_list.remove(
            lines[stmt - 1]
            .replace(" ", "")
            .replace("{", "")
            .replace("}", "")
            .replace("\t", "")
            .replace("\n", "")
            .replace("(", "")
            .replace(")", "")
        )
        if old_new_map[stmt] in new_slicing_set:
            new_slicing_set.remove(old_new_map[stmt])
        vul_syn.remove(stmt)
        indirect_vul_syn.remove(stmt)
        temp_set = set(stmt_list)
        entropy = len(temp_set)
    return vul_syn, new_slicing_set


def signature_generate_vul_patch(
    old_file, new_file, old_method_name, new_method_name, CVE_ID, sess
):
    signature_dict = {}
    worker_id = sess.worker_id.replace("/", "_")
    old_file_location = (
        old_file[: old_file[: old_file.rfind("/")].rfind("/")]
        + "/normalized_"
        + worker_id
        + old_file[old_file.rfind("/") :]
    )
    new_file_location = (
        new_file[: new_file[: new_file.rfind("/")].rfind("/")]
        + "/normalized_"
        + worker_id
        + new_file[new_file.rfind("/") :]
    )
    slicing_set = set()
    old_cdg, old_ddg, old_slicing_set = slicing(old_file, old_method_name, sess)
    new_cdg, new_ddg, new_slicing_set = slicing(new_file, new_method_name, sess)
    old_file = old_file.split("/")[-1]
    new_file = new_file.split("/")[-1]
    vul_syn = old_slicing_set
    old_new_map = {}
    new_old_map = {}
    add_line = []
    worker_id = sess.worker_id.replace("/", "_")
    with open(f"metadata/method_info_{worker_id}.json", "r", encoding="utf8") as f:
        json_object = json.load(f)
        for pair in json_object:
            if old_file == pair["oldFile"]:
                old_function_declaration_line = pair["deleteMethod"][old_method_name][0]
                signature_dict["deleteLines"] = pair["deleteMethod"][old_method_name][
                    1:
                ]
                new_function_declaration_line = pair["addMethod"][new_method_name][0]
                delete_lines = pair["delete"]
                add_lines = pair["add"]
                delete_line = pair["deleteMethod"][old_method_name][1:]
                add_line = pair["addMethod"][new_method_name][1:]
                delete = 1
                add = 1
                for i in range(1, 1000000):
                    while delete in delete_lines:
                        delete += 1
                    while add in add_lines:
                        add += 1
                    old_new_map[delete] = add
                    new_old_map[add] = delete
                    delete += 1
                    add += 1
    indirect_vul_syn = set()
    direct_vul_syn = set()
    for line in new_slicing_set:
        if line not in add_line and line in new_old_map.keys():
            if new_old_map[line] not in vul_syn:
                vul_syn.add(new_old_map[line])

    for line in old_slicing_set:
        for vul in delete_line:
            direct_vul_syn.add(vul)
            if (
                (vul in old_cdg.keys() and line in old_cdg[vul])
                or (vul in old_ddg.keys() and line in old_ddg[vul])
                or (line in old_cdg.keys() and vul in old_cdg[line])
                or (line in old_ddg.keys() and vul in old_ddg[line])
            ):
                direct_vul_syn.add(line)
                break

    for new_line in new_slicing_set:
        for pat in add_line:
            if (
                (pat in new_cdg.keys() and new_line in new_cdg[pat])
                or (pat in new_ddg.keys() and new_line in new_ddg[pat])
                or (new_line in new_cdg.keys() and pat in new_cdg[new_line])
                or (new_line in new_ddg.keys() and pat in new_ddg[new_line])
            ):
                if new_line not in add_line and new_line in new_old_map.keys():
                    direct_vul_syn.add(new_old_map[new_line])
                    break
    indirect_vul_syn = vul_syn.difference(direct_vul_syn)
    print(vul_syn, delete_line, indirect_vul_syn, direct_vul_syn)
    vul_syn, new_slicing_set = entropy_selection(
        vul_syn,
        add_line,
        delete_line,
        indirect_vul_syn,
        old_file,
        old_new_map,
        new_slicing_set,
        worker_id,
    )
    if old_function_declaration_line in vul_syn:
        vul_syn.remove(old_function_declaration_line)
    if old_function_declaration_line in signature_dict["deleteLines"]:
        signature_dict["deleteLines"].remove(old_function_declaration_line)
    vul_sem = []
    for line1 in vul_syn:
        for line2 in vul_syn:
            if line1 in old_cdg.keys():
                if line2 in old_cdg[line1]:
                    vul_sem.append([line1, line2, "control"])
            if line1 in old_ddg.keys():
                if line2 in old_ddg[line1]:
                    vul_sem.append([line1, line2, "data"])
    pat_syn = add_line
    if new_function_declaration_line in pat_syn:
        pat_syn.remove(new_function_declaration_line)

    pat_sem = []
    for line1 in new_slicing_set:
        for line2 in new_slicing_set:
            if line1 not in add_line and line2 not in add_line:
                continue
            if (
                line1 == new_function_declaration_line
                or line2 == new_function_declaration_line
            ):
                continue
            if line1 in new_cdg.keys():
                if line2 in new_cdg[line1]:
                    pat_sem.append([line1, line2, "control"])
            if line1 in new_ddg.keys():
                if line2 in new_ddg[line1]:
                    pat_sem.append([line1, line2, "data"])
    vul_syn = list(vul_syn)
    vul_sem = list(vul_sem)
    hash_delete_lines = []
    hash_vul_syn = {}
    hash_vul_sem = {}
    hash_pat_syn = {}
    hash_pat_sem = {}
    with open(old_file_location, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        for i in range(len(signature_dict["deleteLines"])):
            signature_dict["deleteLines"][i] = (
                lines[signature_dict["deleteLines"][i] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
                .replace("(", "")
                .replace(")", "")
            )
            if signature_dict["deleteLines"][i] != "":
                m = hashlib.md5()
                m.update(
                    signature_dict["deleteLines"][i].encode("GBK", errors="ignore")
                )
                hash_delete_lines.append(m.hexdigest()[:6])
        for i in range(len(vul_syn)):
            lineNumber = copy.deepcopy(vul_syn[i])
            vul_syn[i] = (
                lines[vul_syn[i] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
                .replace("(", "")
                .replace(")", "")
            )
            if vul_syn[i] != "":
                m = hashlib.md5()
                m.update(vul_syn[i].encode("GBK", errors="ignore"))
                hash_vul_syn[lineNumber] = m.hexdigest()[:6]
        for i in range(len(vul_sem)):
            tuple1 = vul_sem[i]
            line_tuple = copy.deepcopy(tuple1)
            tuple1[0] = (
                lines[tuple1[0] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
                .replace("(", "")
                .replace(")", "")
            )
            tuple1[1] = (
                lines[tuple1[1] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
                .replace("(", "")
                .replace(")", "")
            )
            if tuple1[0] != "" and tuple1[1] != "":
                tuple2 = []
                m = hashlib.md5()
                m.update(tuple1[0].encode("GBK", errors="ignore"))
                tuple2.append(m.hexdigest()[:6])
                m = hashlib.md5()
                m.update(tuple1[1].encode("GBK", errors="ignore"))
                tuple2.append(m.hexdigest()[:6])
                tuple2.append(tuple1[2])
                line_tuple = (str(item) for item in line_tuple)
                line_tuple_str = "__split__".join(line_tuple)
                hash_vul_sem[line_tuple_str] = tuple2
    with open(new_file_location, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        for i in range(len(pat_syn)):
            lineNumber = copy.deepcopy(pat_syn[i])
            pat_syn[i] = (
                lines[pat_syn[i] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
                .replace("(", "")
                .replace(")", "")
            )
            if pat_syn[i] != "":
                m = hashlib.md5()
                m.update(pat_syn[i].encode("GBK", errors="ignore"))
                hash_pat_syn[lineNumber] = m.hexdigest()[:6]
        for i in range(len(pat_sem)):
            tuple1 = pat_sem[i]
            line_tuple = copy.deepcopy(tuple1)
            tuple1[0] = (
                lines[tuple1[0] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
                .replace("(", "")
                .replace(")", "")
            )
            tuple1[1] = (
                lines[tuple1[1] - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
                .replace("(", "")
                .replace(")", "")
            )
            if tuple1[0] != "" and tuple1[1] != "":
                tuple2 = []
                m = hashlib.md5()
                m.update(tuple1[0].encode("GBK", errors="ignore"))
                tuple2.append(m.hexdigest()[:6])
                m = hashlib.md5()
                m.update(tuple1[1].encode("GBK", errors="ignore"))
                tuple2.append(m.hexdigest()[:6])
                tuple2.append(tuple1[2])
                line_tuple = (str(item) for item in line_tuple)
                line_tuple_str = "__split__".join(line_tuple)
                hash_pat_sem[line_tuple_str] = tuple2
    signature_dict["deleteLines"] = hash_delete_lines
    signature_dict["vul_syn"] = hash_vul_syn
    signature_dict["vul_sem"] = hash_vul_sem
    signature_dict["pat_syn"] = hash_pat_syn
    signature_dict["pat_sem"] = hash_pat_sem
    signature_dict = reformat_sig(signature_dict)
    return signature_dict


def reformat_sig(sig):
    re_sig = {}
    re_sig["deleteLines"] = sig["deleteLines"]
    re_sig["vul_syn"] = sig["vul_syn"]
    re_sig["vul_sem"] = sig["vul_sem"]
    re_sig["vul_merge"] = {}
    for syn in sig["vul_syn"]:
        re_sig["vul_merge"][syn] = []
        for sem in sig["vul_sem"]:
            line_rela = sem.split("__split__")
            lineNumber1 = line_rela[0]
            lineNumber2 = line_rela[1]
            if int(syn) == int(lineNumber1) or int(syn) == int(lineNumber2):
                re_sig["vul_merge"][syn].append(sig["vul_sem"][sem])
    re_sig["pat_syn"] = sig["pat_syn"]
    re_sig["pat_sem"] = sig["pat_sem"]
    re_sig["pat_merge"] = {}
    for syn in sig["pat_syn"]:
        re_sig["pat_merge"][syn] = []
        for sem in sig["pat_sem"]:
            line_rela = sem.split("__split__")
            lineNumber1 = line_rela[0]
            lineNumber2 = line_rela[1]
            if int(syn) == int(lineNumber1) or int(syn) == int(lineNumber2):
                re_sig["pat_merge"][syn].append(sig["pat_sem"][sem])
    return re_sig


def signature_generate_function(
    CVE_ID,
    file_name,
    method_name,
    method_line_number_start,
    method_line_number_end,
    sess,
):
    signature_dict = {}
    with open(file_name, "r") as f:
        lines = f.readlines()
        signature_dict["syn"] = {}
        for i in range(method_line_number_start + 1, method_line_number_end + 1):
            syn_line = (
                lines[i - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
                .replace("(", "")
                .replace(")", "")
            )
            if syn_line != "":
                m = hashlib.md5()
                m.update(syn_line.encode("utf8"))
                signature_dict["syn"][i] = m.hexdigest()[:6]
    sess.import_code(file_name)
    worker_id = sess.worker_id.replace("/", "_")
    sess.run_script(
        "slice", params={"line": method_line_number_start, "cveid": str(worker_id)}
    )
    label_line_map = {}
    cdg_map = {}
    ddg_map = {}
    with open(f"metadata/PDG_{worker_id}.json", "r", encoding="utf8") as f:
        json_object = json.load(f)
        if len(json_object) == 0:
            signature_dict["sem"] = {}
            signature_dict["merge"] = {}
            for syn in signature_dict["syn"]:
                signature_dict["merge"][syn] = []
            return signature_dict
        list1 = json_object[0].split("\n")
        signature_dict["merge"] = {}
        for line in list1:
            if not line.startswith("digraph"):
                if line.startswith('"'):
                    num_end = line.find('"', 1)
                    label_number = int(line[1:num_end])
                    line_number_start = line.find("<SUB>")
                    line_number_end = line.find("</SUB>")
                    if line_number_start == -1 or line_number_end == -1:
                        continue
                    line_number = int(line[line_number_start + 5 : line_number_end])
                    label_line_map[label_number] = line_number
                elif len(line) > 1:
                    from_end = line.find('"', 3)
                    from_label = int(line[3:from_end])
                    to_start = line.find('"', from_end + 1)
                    to_end = line.find('"', to_start + 1)
                    to_label = int(line[to_start + 1 : to_end])
                    label_start = line.find('[ label = "')
                    label = line[label_start + 11 : -3]
                    if (
                        from_label not in label_line_map.keys()
                        or to_label not in label_line_map.keys()
                    ):
                        continue
                    if label_line_map[from_label] != label_line_map[to_label]:
                        if label.startswith("CDG"):
                            if label_line_map[from_label] not in cdg_map.keys():
                                cdg_map[label_line_map[from_label]] = set()
                            cdg_map[label_line_map[from_label]].add(
                                label_line_map[to_label]
                            )
                        else:
                            if label_line_map[from_label] not in ddg_map.keys():
                                ddg_map[label_line_map[from_label]] = set()
                            ddg_map[label_line_map[from_label]].add(
                                label_line_map[to_label]
                            )
    signature_dict["sem"] = {}
    for i in range(method_line_number_start + 1, method_line_number_end):
        if i in cdg_map.keys():
            for j in cdg_map[i]:
                if i != j and j != method_line_number_start:
                    sem_line1 = (
                        lines[i - 1]
                        .replace(" ", "")
                        .replace("{", "")
                        .replace("}", "")
                        .replace("\t", "")
                        .replace("\n", "")
                        .replace("(", "")
                        .replace(")", "")
                    )
                    sem_line2 = (
                        lines[j - 1]
                        .replace(" ", "")
                        .replace("{", "")
                        .replace("}", "")
                        .replace("\t", "")
                        .replace("\n", "")
                        .replace("(", "")
                        .replace(")", "")
                    )
                    if sem_line1 != "" and sem_line2 != "":
                        tuple1 = []
                        m = hashlib.md5()
                        m.update(sem_line1.encode("utf8"))
                        tuple1.append(m.hexdigest()[:6])
                        m = hashlib.md5()
                        m.update(sem_line2.encode("utf8"))
                        tuple1.append(m.hexdigest()[:6])
                        tuple1.append("control")
                        line_tuple = copy.deepcopy(tuple1)
                        line_tuple = (str(item) for item in line_tuple)
                        line_tuple_str = "__split__".join([i.__str__(), j.__str__()])
                        signature_dict["sem"][line_tuple_str] = tuple1
        if i in ddg_map.keys():
            for j in ddg_map[i]:
                if i != j and j != method_line_number_start:
                    sem_line1 = (
                        lines[i - 1]
                        .replace(" ", "")
                        .replace("{", "")
                        .replace("}", "")
                        .replace("\t", "")
                        .replace("\n", "")
                        .replace("(", "")
                        .replace(")", "")
                    )
                    sem_line2 = (
                        lines[j - 1]
                        .replace(" ", "")
                        .replace("{", "")
                        .replace("}", "")
                        .replace("\t", "")
                        .replace("\n", "")
                        .replace("(", "")
                        .replace(")", "")
                    )
                    if sem_line1 != "" and sem_line2 != "":
                        tuple1 = []
                        m = hashlib.md5()
                        m.update(sem_line1.encode("utf8"))
                        tuple1.append(m.hexdigest()[:6])
                        m = hashlib.md5()
                        m.update(sem_line2.encode("utf8"))
                        tuple1.append(m.hexdigest()[:6])
                        tuple1.append("data")
                        line_tuple = copy.deepcopy(tuple1)
                        line_tuple = (str(item) for item in line_tuple)
                        line_tuple_str = "__split__".join([i.__str__(), j.__str__()])
                        signature_dict["sem"][line_tuple_str] = tuple1
    for syn in signature_dict["syn"]:
        signature_dict["merge"][syn] = []
        for sem in signature_dict["sem"]:
            line_rela = sem.split("__split__")
            lineNumber1 = line_rela[0]
            lineNumber2 = line_rela[1]
            if int(syn) == int(lineNumber1) or int(syn) == int(lineNumber2):
                signature_dict["merge"][syn].append(signature_dict["sem"][sem])
    return signature_dict


def jsonify(worker_id):
    with open(f"metadata/LV_{worker_id}.json", "r", encoding="utf8") as f:
        fp = f.readlines()
        lines = []
        for fpline in fp:
            rawlist = fpline.rsplit(",", maxsplit=2)
            if rawlist[1] == "None" or rawlist[2] == "None":
                continue
            dict = {}
            dict["_1"] = rawlist[0][1:]
            dict["_2"] = int(rawlist[1][5:-1])
            if fpline[-1] == "\n":
                dict["_3"] = int(rawlist[2][5:-3])
            else:
                dict["_3"] = int(rawlist[2][5:-2])
            lines.append(dict)
    with open(f"metadata/newLV_{worker_id}.json", "w", encoding="utf8") as f:
        f.writelines(json.dumps(lines))


def format_and_del_comment(src):
    with open(src, "r", encoding=encoding_format) as f:
        file_contents = f.read()
    c_regex = re.compile(
        r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE,
    )
    with open(src, "w", encoding=encoding_format) as f:
        f.write(
            "".join(
                [
                    c.group("noncomment")
                    for c in c_regex.finditer(file_contents)
                    if c.group("noncomment")
                ]
            )
        )
    with open(src, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            if lines[i].endswith("\\\n"):
                temp = i
                while lines[i].endswith("\\\n"):
                    i += 1
                lines[temp] = lines[temp][:-2]
                for k in range(temp + 1, i + 1):
                    if k == len(lines):
                        break
                    lines[temp] += " "
                    lines[temp] += lines[k][:-2].strip()
                    lines[k] = "\n"
            else:
                i += 1
    with open(src, "w", encoding=encoding_format) as f:
        f.writelines(lines)

    with open(src, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        for i in range(len(lines)):
            if lines[i].startswith("#"):
                lines[i] = "\n"
    with open(src, "w", encoding=encoding_format) as f:
        f.writelines(lines)
    with open(src, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            if (
                lines[i].strip() == "\n"
                or lines[i].strip() == "\r\n"
                or lines[i].strip() == ""
            ):
                i += 1
            else:
                temp = i
                while (
                    i < len(lines)
                    and not lines[i].strip().endswith(";")
                    and not lines[i].strip().endswith("{")
                    and not lines[i].strip().endswith(")")
                    and not lines[i].strip().endswith("}")
                    and not lines[i].strip().endswith(":")
                    and not lines[i].strip().startswith("#")
                ):
                    i += 1
                if temp != i:
                    lines[temp] = lines[temp][:-1]
                for j in range(temp + 1, i + 1):
                    if j == len(lines):
                        break
                    lines[temp] += " "
                    lines[temp] += lines[j][:-1].strip()
                    lines[j] = "\n"
                if temp == i:
                    i += 1
    with open(src, "w", encoding=encoding_format) as f:
        f.writelines(lines)


def gen_fingerprint(CVE_ID, commit_file_location, git_repo_location, work_dir, sess):
    worker_id = sess.worker_id.replace("/", "_")
    if not os.path.exists(f"{work_dir}/temp_" + worker_id):
        os.system(f"mkdir {work_dir}/temp_" + worker_id)
    if not os.path.exists(f"{work_dir}/normalized_" + worker_id):
        os.system(f"mkdir {work_dir}/normalized_" + worker_id)
    print(CVE_ID, commit_file_location, git_repo_location, work_dir)
    os.chdir(git_repo_location)
    with open(commit_file_location, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        commit_id = lines[0].split(" ")[1]
    readCommit(CVE_ID, commit_file_location, git_repo_location, work_dir, sess)
    os.chdir(work_dir)
    with open(f"metadata/method_info_{worker_id}.json") as f:
        json_list = json.load(f)
        for ele in json_list:
            os.system(
                "cp "
                + work_dir
                + "temp_"
                + worker_id
                + "/"
                + ele["oldFile"]
                + " normalized_"
                + worker_id
                + "/"
                + ele["oldFile"]
            )
            for method in ele["deleteMethod"]:
                print("normalize!")
                sess.import_code(work_dir + "temp_" + worker_id + "/" + ele["oldFile"])
                sess.run_script(
                    "normalize",
                    params={
                        "line": ele["deleteMethod"][method][0],
                        "cveid": str(worker_id),
                    },
                )
                jsonify(worker_id)
                parse("normalized_" + worker_id + "/" + ele["oldFile"], worker_id)
            os.system(
                "cp "
                + work_dir
                + "temp_"
                + worker_id
                + "/"
                + ele["newFile"]
                + " normalized_"
                + worker_id
                + "/"
                + ele["newFile"]
            )
            for method in ele["addMethod"]:
                sess.import_code(work_dir + "temp_" + worker_id + "/" + ele["newFile"])
                sess.run_script(
                    "normalize",
                    params={
                        "line": ele["addMethod"][method][0],
                        "cveid": str(worker_id),
                    },
                )
                jsonify(worker_id)
                parse("normalized_" + worker_id + "/" + ele["newFile"], worker_id)
    add_method_cnt = 0
    delete_method_cnt = 0
    change_method_cnt = 0
    with open(f"metadata/method_info_{worker_id}.json") as f:
        multi_method_signature = dict()
        json_list = json.load(f)
        for ele in json_list:
            for method in ele["deleteMethod"].keys():
                if (
                    method not in ele["addMethod"].keys()
                    and method not in ele["change_method_map"].keys()
                ):
                    continue
                elif method in ele["change_method_map"].keys():
                    change_method_cnt += 1
                    multi_method_signature[
                        ele["oldFile"]
                        + "__split__"
                        + ele["newFile"]
                        + "__split__"
                        + method
                        + "__split__"
                        + ele["change_method_map"][method]
                    ] = signature_generate_vul_patch(
                        work_dir + "temp_" + worker_id + "/" + ele["oldFile"],
                        work_dir + "temp_" + worker_id + "/" + ele["newFile"],
                        method,
                        ele["change_method_map"][method],
                        CVE_ID,
                        sess,
                    )
                else:
                    multi_method_signature[
                        ele["oldFile"]
                        + "__split__"
                        + ele["newFile"]
                        + "__split__"
                        + method
                    ] = signature_generate_vul_patch(
                        work_dir + "temp_" + worker_id + "/" + ele["oldFile"],
                        work_dir + "temp_" + worker_id + "/" + ele["newFile"],
                        method,
                        method,
                        CVE_ID,
                        sess,
                    )
            if "pureAddMethod" in ele.keys():
                for pureAddMethod in ele["pureAddMethod"]:
                    for method in pureAddMethod.keys():
                        add_method_cnt += 1
                        multi_method_signature[
                            ele["newFile"] + "__split__" + method
                        ] = signature_generate_function(
                            CVE_ID,
                            "normalized_" + worker_id + "/" + ele["newFile"],
                            method,
                            pureAddMethod[method][0],
                            pureAddMethod[method][1],
                            sess,
                        )
            if "pureDeleteMethod" in ele.keys():
                for pureDeleteMethod in ele["pureDeleteMethod"]:
                    for method in pureDeleteMethod.keys():
                        delete_method_cnt += 1
                        multi_method_signature[
                            "del__split__" + ele["oldFile"] + "__split__" + method
                        ] = signature_generate_function(
                            CVE_ID,
                            "normalized_" + worker_id + "/" + ele["oldFile"],
                            method,
                            pureDeleteMethod[method][0],
                            pureDeleteMethod[method][1],
                            sess,
                        )
    with open(
        "./signature/" + CVE_ID + ".json",
        "w",
        encoding="utf8",
    ) as f:
        json.dump(multi_method_signature, f)


def dfmp(
    df,
    function,
    columns=None,
    ordr=True,
    workers=1,
    cs=10,
    desc="Run: ",
    generator=False,
    total=None,
):
    items = df
    it = _dfmp(function, items, ordr, workers, cs, desc, total)
    if generator:
        return it
    else:
        processed = []
        processed.extend(it)
        return processed


def _dfmp(function, items, ordr, workers, cs, desc, total):
    if desc is not None:
        desc = f"({workers} Workers) {desc}"
    with Pool(processes=workers) as p:
        map_func = getattr(p, "imap" if ordr else "imap_unordered")
        it = map_func(function, items, cs)
        if desc is not None:
            try:
                items_len = len(items)
            except:
                if total is not None:
                    items_len = total
                else:
                    items_len = None
            it = tqdm(it, total=items_len, desc=desc)
        yield from it


def preprocess(row, fn, sess):
    CVE_ID, commit_file_location, git_repo_location, work_dir = (
        row["CVE"],
        row["commit_file_location"],
        row["git_repo_location"],
        row["work_dir"],
    )
    print(CVE_ID, commit_file_location, git_repo_location, work_dir)
    fn(CVE_ID, commit_file_location, git_repo_location, work_dir, sess)


def preprocess_whole_df_split(t):
    """
    preprocess one split of the dataframe
    """
    i, split = t
    print(t)
    with open(f"hpc/logs/getgraphs_output_{i}.joernlog", "wb") as lf:
        sess = joern_session.JoernSession(f"fingerprint/{i}", logfile=lf, clean=True)
        try:
            fn = functools.partial(
                gen_fingerprint,
            )
            items = split.to_dict("records")
            position = 0 if not isinstance(i, int) else int(i)

            for row in tqdm(items, desc=f"(worker {i})", position=position):
                CVE_ID = row["CVE"]
                time0 = time.time()
                preprocess(row, fn, sess)
                time1 = time.time()
                time_info[CVE_ID] = time1 - time0
                fp = open(
                    f"./sigs_time_{sess.worker_id.replace('/','_')}.json",
                    "w",
                )
                json.dump(time_info, fp, indent=4)
                fp.close()
        finally:
            os.system(f"rm -r workers/{sess.worker_id}")
            sess.close()


if __name__ == "__main__":
    set_joern_env(JOERN_PATH)
    time_info = {}
    for i in range(16):
        fp = open(f"sigs_time_fingerprint_{i}.json")
        info = json.load(fp)
        fp.close()
        time_info.update(info)

    df = pd.read_csv("CVEdataset.csv")
    run = []
    for row in df.to_dict("records"):
        if row["CVE"] not in time_info.keys() or row["CVE"] == "CVE-2020-24370":
            run.append(row)

    df = pd.DataFrame(run)
    df.to_csv("runs.csv", index=False)
    df = pd.read_csv("runs.csv")
    workers = 1
    if os.path.exists("./workers"):
        os.system("rm -r ./workers")
    if workers == 1:
        preprocess_whole_df_split(("all", df))
    else:
        splits = np.array_split(df, workers)
        dfmp(
            enumerate(splits),
            preprocess_whole_df_split,
            ordr=False,
            workers=workers,
            cs=1,
        )
