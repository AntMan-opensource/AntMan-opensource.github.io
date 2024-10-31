import copy
import functools
import hashlib
import json
import logging
import os
import pickle
import re
import subprocess
import sys
import time
import traceback
from datetime import datetime
from multiprocessing import Lock, Pool
from queue import Queue
from xml.dom.minidom import parse

import cpu_heater
import joern_session
import numpy as np
import pandas as pd
from getOperator import ASTParser
from tqdm import tqdm

encoding_format = "ISO-8859-1"
TS_METHOD = "(function_definition) @method"
TS_LVAR = "(declaration     (init_declarator (identifier)@identifier))"
TS_FPARAM = "(parameter_list (parameter_declaration (identifier)@name))(parameter_list (parameter_declaration (pointer_declarator)@name))"
TS_FUNCCALL = "(call_expression    (identifier)@name)"
TS_DTYPE = "(type_identifier)@ID (primitive_type)@name"
TS_STR = "(string_literal) @method"
file = open("./config.json")
info = json.load(file)
file.close()
work_dir = info["work_path"]
signature_path = info["signature_path"]
progress_file = info["progress_file"]
tempSignature = info["tempSignature_multi"]
th_syn_v = info["th_syn_v"]
th_sem_v = info["th_sem_v"]
th_syn_p = info["th_syn_p"]
th_sem_p = info["th_sem_p"]
th_ce = info["th_ce"]

tmp_tar_file = {}

lock = Lock()
detecteds = []
CVE_dict = {}
with open("./infoFile/sagaMulti.json", "r") as f:
    cves = json.load(f)
    for cve in cves:
        CVE_dict[cve] = cves[cve]
CVE_sigs = {}
for CVE in os.listdir("./signature"):
    with open("./signature/" + CVE, "r") as f:
        CVE_sigs[CVE.replace(".json", "")] = json.load(f)
originalDir = os.path.dirname(os.path.abspath(__file__))


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


def parse(file_location, i, worker_id):
    CONST_DICT = {"FP": "FPARAM", "LV": "LVAR", "DT": "DTYPE", "FC": "FUNCCALL"}
    FP_coor_list = []
    LV_coor_list = []
    DT_coor_list = []
    FC_coor_list = []
    with open(
        f"{work_dir}normalizeJson_" + worker_id + "/FP" + i.__str__() + ".json",
        "r",
        encoding="utf8",
    ) as f:
        FP_coor_list = json.load(f)
    with open(
        f"{work_dir}normalizeJson_" + worker_id + "/newLV" + i.__str__() + ".json",
        "r",
        encoding="utf8",
    ) as f:
        LV_coor_list = json.load(f)
    with open(
        f"{work_dir}normalizeJson_" + worker_id + "/DT" + i.__str__() + ".json",
        "r",
        encoding="utf8",
    ) as f:
        DT_coor_list = json.load(f)
    with open(
        f"{work_dir}normalizeJson_" + worker_id + "/FC" + i.__str__() + ".json",
        "r",
        encoding="utf8",
    ) as f:
        FC_coor_list = json.load(f)
    with open(
        f"{work_dir}normalizeJson_" + worker_id + "/STRING" + i.__str__() + ".json",
        "r",
        encoding="utf8",
    ) as f:
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


def jsonify(i, worker_id):
    with open(
        f"{work_dir}normalizeJson_" + worker_id + "/LV" + i.__str__() + ".json",
        "r",
        encoding="utf8",
    ) as f:
        fp = f.readlines()
        lines = []
        for fpline in fp:
            if "Some" not in fpline:
                continue
            index_some = fpline.find("Some")
            if "Some" not in fpline[index_some + 3 :]:
                continue
            index_some2 = fpline[index_some + 3 :].find("Some")
            dict = {}
            dict["_1"] = fpline[1 : index_some - 1]
            dict["_2"] = int(fpline[index_some + 5 : index_some + 3 + index_some2 - 2])
            if fpline[-1] == "\n":
                dict["_3"] = int(fpline[index_some + 4 + index_some2 + 4 : -3])
            else:
                dict["_3"] = int(fpline[index_some + 4 + index_some2 + 4 : -2])
            lines.append(dict)
    with open(
        f"{work_dir}normalizeJson_" + worker_id + "/newLV" + i.__str__() + ".json",
        "w",
        encoding="utf8",
    ) as f:
        f.writelines(json.dumps(lines))


def detect_get_method_list(detect_dir, detect_file, method_list, sess):
    os.chdir(work_dir)
    worker_id = sess.worker_id.replace("/", "_")
    for file_name in os.listdir(detect_file):
        format_and_del_comment(detect_file + "/" + file_name)
        os.system(
            'cp "'
            + detect_file
            + "/"
            + file_name
            + '" '
            + work_dir
            + '"normalized_'
            + worker_id
            + "/"
            + file_name
            + '"'
        )
    try:
        sess.import_code(detect_file)
        sess.run_script("metadata", params={"cveid": str(worker_id)})
        with open(f"./metadata/method_{worker_id}.json") as f:
            json_obj = json.load(f)
            for obj in json_obj:
                if (
                    "lineNumber" in obj.keys()
                    and obj["fullName"] != ":<global>"
                    and "signature" in obj.keys()
                    and obj["signature"] != ""
                ):
                    method_list.append(
                        [
                            obj["code"],
                            obj["lineNumber"],
                            obj["lineNumberEnd"],
                            obj["filename"],
                        ]
                    )
        method_list_json = []
        for method_info in method_list:
            method_list_json.append(
                {
                    "signature": method_info[0],
                    "lineNumber": method_info[1],
                    "lineNumberEnd": method_info[2],
                    "filename": method_info[3],
                }
            )
        with open(
            f"./metadata/method_filtered_{worker_id}.json", "w", encoding="utf8"
        ) as f:
            json.dump(method_list_json, f)
        return method_list
    except Exception as e:
        print(str(e))
        print("Error when detecting file:" + detect_file)


def detect_normalize1(file_name, i, worker_id):
    jsonify(i, worker_id)
    parse(work_dir + "normalized_" + worker_id + "/" + file_name, i, worker_id)


def detect_slicing1(i, worker_id):
    label_line_map = {}
    cdg_map = {}
    ddg_map = {}
    with open(
        f"{work_dir}slicingJson_" + worker_id + "/PDG" + i.__str__() + ".json",
        "r",
        encoding="utf8",
    ) as f:
        json_object = json.load(f)
        if len(json_object) == 0:
            return cdg_map, ddg_map
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
    return cdg_map, ddg_map


def detect_generate_signature(
    file_name, method_info, cdg_map, ddg_map, work_dir, worker_id
):
    func_syn = {}
    func_sem = {}
    func_merge = {}
    with open(
        work_dir + "normalized_" + worker_id + "/" + file_name,
        "r",
        encoding=encoding_format,
    ) as f:
        lines = f.readlines()
        for i in range(method_info[1] + 1, method_info[2] + 1):
            temp_str = (
                lines[i - 1]
                .replace(" ", "")
                .replace("{", "")
                .replace("}", "")
                .replace("\t", "")
                .replace("\n", "")
                .replace("(", "")
                .replace(")", "")
            )
            if temp_str != "":
                m = hashlib.md5()
                m.update(temp_str.encode(encoding_format))
                func_syn[str(i)] = m.hexdigest()[:6]
        for key in cdg_map.keys():
            if not method_info[1] + 1 <= key <= method_info[2]:
                continue
            for line in cdg_map[key]:
                if method_info[1] + 1 <= line <= method_info[2]:
                    temp_str1 = (
                        lines[key - 1]
                        .replace(" ", "")
                        .replace("{", "")
                        .replace("}", "")
                        .replace("\t", "")
                        .replace("\n", "")
                        .replace("(", "")
                        .replace(")", "")
                    )
                    temp_str2 = (
                        lines[line - 1]
                        .replace(" ", "")
                        .replace("{", "")
                        .replace("}", "")
                        .replace("\t", "")
                        .replace("\n", "")
                        .replace("(", "")
                        .replace(")", "")
                    )
                    if temp_str1 != "" and temp_str2 != "":
                        tuple1 = []
                        m = hashlib.md5()
                        m.update(temp_str1.encode(encoding_format))
                        tuple1.append(m.hexdigest()[:6])
                        m = hashlib.md5()
                        m.update(temp_str2.encode(encoding_format))
                        tuple1.append(m.hexdigest()[:6])
                        tuple1.append("control")
                        line_tuple_str = (
                            str(key) + "__split__" + str(line) + "__split__control"
                        )
                        func_sem[line_tuple_str] = tuple1
                        if str(key) not in func_merge.keys():
                            func_merge[str(key)] = []
                        if str(line) not in func_merge.keys():
                            func_merge[str(line)] = []
                        func_merge[str(key)].append(tuple1)
                        func_merge[str(line)].append(tuple1)
        for key in ddg_map.keys():
            if not method_info[1] + 1 <= key <= method_info[2]:
                continue
            for line in ddg_map[key]:
                if method_info[1] + 1 <= line <= method_info[2]:
                    temp_str1 = (
                        lines[key - 1]
                        .replace(" ", "")
                        .replace("{", "")
                        .replace("}", "")
                        .replace("\t", "")
                        .replace("\n", "")
                        .replace("(", "")
                        .replace(")", "")
                    )
                    temp_str2 = (
                        lines[line - 1]
                        .replace(" ", "")
                        .replace("{", "")
                        .replace("}", "")
                        .replace("\t", "")
                        .replace("\n", "")
                        .replace("(", "")
                        .replace(")", "")
                    )
                    if temp_str1 != "" and temp_str2 != "":
                        tuple1 = []
                        m = hashlib.md5()
                        m.update(temp_str1.encode(encoding_format))
                        tuple1.append(m.hexdigest()[:6])
                        m = hashlib.md5()
                        m.update(temp_str2.encode(encoding_format))
                        tuple1.append(m.hexdigest()[:6])
                        tuple1.append("data")
                        line_tuple_str = (
                            str(key) + "__split__" + str(line) + "__split__data"
                        )
                        func_sem[line_tuple_str] = tuple1
                        if str(key) not in func_merge.keys():
                            func_merge[str(key)] = []
                        if str(line) not in func_merge.keys():
                            func_merge[str(line)] = []
                        func_merge[str(key)].append(tuple1)
                        func_merge[str(line)].append(tuple1)
    return func_syn, func_sem, func_merge


def generate_signature_in_file(detect_dir, file, cnt, sess):
    method_list = []
    method_list = detect_get_method_list(detect_dir, file, method_list, sess)
    if method_list is None:
        return
    os.chdir(work_dir)
    worker_id = sess.worker_id.replace("/", "_")
    sess.run_script(
        "slice_per",
        params={
            "filePath": f"./metadata/method_filtered_{worker_id}.json",
            "i": str(worker_id),
        },
    )
    sess.run_script(
        "normalize_per",
        params={
            "filePath": f"./metadata/method_filtered_{worker_id}.json",
            "i": str(worker_id),
        },
    )

    i = 0
    index_to_file_dict = {}
    for method_info in method_list:
        cnt += 1
        detect_normalize1(method_info[3].split("/")[-1], i, worker_id)
        cdg_map, ddg_map = detect_slicing1(i, worker_id)
        func_syn, func_sem, func_merge = detect_generate_signature(
            method_info[3].split("/")[-1],
            method_info,
            cdg_map,
            ddg_map,
            work_dir,
            worker_id,
        )
        with open(tempSignature + worker_id + "/" + cnt.__str__() + ".json", "w") as f:
            json.dump(
                {
                    "func_syn": func_syn,
                    "func_sem": func_sem,
                    "func_merge": func_merge,
                    "file_name": method_info[3].split("/")[-1],
                    "method_name": method_info[0],
                    "line_number": method_info[1].__str__(),
                },
                f,
            )
        index_to_file_dict[cnt] = {
            "file_name": method_info[3].split("/")[-1],
            "method_name": method_info[0],
            "line_number": method_info[1].__str__(),
        }
        i += 1

    return index_to_file_dict


def detect_dirs(detect_dir, file, CVEList, sess):
    worker_id = sess.worker_id.replace("/", "_")
    if not os.path.exists(f"{work_dir}normalized_" + worker_id):
        os.system(f"mkdir {work_dir}normalized_" + worker_id)
    if not os.path.exists(tempSignature + worker_id):
        os.system(f"mkdir {tempSignature}{worker_id}")
    if not os.path.exists(f"{work_dir}normalizeJson_" + worker_id):
        os.system(f"mkdir {work_dir}normalizeJson_" + worker_id)
    if not os.path.exists(f"{work_dir}slicingJson_" + worker_id):
        os.system(f"mkdir {work_dir}slicingJson_" + worker_id)
    ans_list = {}
    try:
        total_index_to_method_dict = {}
        index_to_method_dict = {}
        index_to_method_dict = generate_signature_in_file(
            detect_dir, file, len(total_index_to_method_dict), sess
        )
        for index in index_to_method_dict:
            total_index_to_method_dict[index] = index_to_method_dict[index]
    except Exception as e:
        print("Error when detect file " + file + " exception is ")
        print(e)
    sus_method_dict = {}
    for index in total_index_to_method_dict.keys():
        with open(
            tempSignature + worker_id + "/" + index.__str__() + ".json", "r"
        ) as f:
            sus_method_dict[index] = json.load(f)
    index1 = 0
    total = len(CVEList)
    for CVE in CVEList:
        index1 += 1
        with open(signature_path + CVE + ".json", "r") as f:
            sig = json.load(f)
            match_dict = {}
            with open(progress_file, "a") as f:
                now_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(
                    "["
                    + now_time
                    + "]"
                    + " Matching "
                    + CVE
                    + " now. Progress:"
                    + index1.__str__()
                    + "/"
                    + total.__str__()
                    + "\n"
                )
            for key in sig.keys():
                if key.count("__split__") >= 2 and not key.startswith("del"):
                    delete_lines = sig[key]["deleteLines"]
                    vul_syn = sig[key]["vul_syn"]
                    vul_sem = sig[key]["vul_sem"]
                    pat_syn = sig[key]["pat_syn"]
                    pat_sem = sig[key]["pat_sem"]
                    if len(vul_sem) == 0:
                        continue
                    split_list = key.split("__split__")
                    match_dict[split_list[0] + "__split__" + split_list[2]] = []
                    for index in sus_method_dict:
                        sus_method_syn = copy.deepcopy(
                            sus_method_dict[index]["func_syn"]
                        )
                        sus_method_sem = copy.deepcopy(
                            sus_method_dict[index]["func_sem"]
                        )
                        method_name = sus_method_dict[index]["method_name"]
                        filename = tmp_tar_file[sus_method_dict[index]["file_name"]]
                        is_match = True
                        if filename not in ans_list.keys():
                            ans_list[filename] = {}
                        if CVE not in ans_list[filename].keys():
                            ans_list[filename][CVE] = {}
                        if key not in ans_list[filename][CVE].keys():
                            ans_list[filename][CVE][key] = {}
                        if method_name not in ans_list[filename][CVE][key].keys():
                            ans_list[filename][CVE][key][method_name] = {}
                        ans_list[filename][CVE][key][method_name]["line_number"] = (
                            sus_method_dict[index]["line_number"]
                        )
                        is_match = True
                        for line in delete_lines:
                            flag = False
                            match_id = 0
                            for id in sus_method_syn:
                                if line == sus_method_syn[id]:
                                    flag = True
                                    match_id = id
                                    break
                            if not flag:
                                is_match = False
                                break
                            else:
                                del sus_method_syn[match_id]
                        ans_list[filename][CVE][key][method_name]["del"] = is_match
                        sus_method_syn = copy.deepcopy(
                            sus_method_dict[index]["func_syn"]
                        )
                        cnt_vul_syn = 0
                        for idx in vul_syn:
                            for idx_tgt in sus_method_syn:
                                if vul_syn[idx] == sus_method_syn[idx_tgt]:
                                    del sus_method_syn[idx_tgt]
                                    cnt_vul_syn += 1
                                    break
                        if (
                            len(set(vul_syn)) > 0
                            and cnt_vul_syn / len(vul_syn) <= th_syn_v
                        ):
                            is_match = False
                            ans_list[filename][CVE][key][method_name]["vul_syn"] = False
                        else:
                            ans_list[filename][CVE][key][method_name]["vul_syn"] = True

                        sus_method_syn = copy.deepcopy(
                            sus_method_dict[index]["func_syn"]
                        )
                        sus_method_sem = copy.deepcopy(
                            sus_method_dict[index]["func_sem"]
                        )
                        cnt_match_vul_sem = 0
                        for idx in vul_sem:
                            three_tuple_vul_sem = vul_sem[idx]
                            for idx_tgt in sus_method_sem:
                                if three_tuple_vul_sem == sus_method_sem[idx_tgt]:
                                    del sus_method_sem[idx_tgt]
                                    cnt_match_vul_sem += 1
                                    break
                        ans_list[filename][CVE][key][method_name]["score"] = (
                            cnt_match_vul_sem / len(vul_sem)
                        )
                        if (
                            len(vul_sem) > 0
                            and cnt_match_vul_sem / len(vul_sem) <= th_sem_v
                        ):
                            is_match = False
                            ans_list[filename][CVE][key][method_name]["vul_sem"] = False
                        else:
                            ans_list[filename][CVE][key][method_name]["vul_sem"] = True

                        sus_method_syn = copy.deepcopy(
                            sus_method_dict[index]["func_syn"]
                        )
                        sus_method_sem = copy.deepcopy(
                            sus_method_dict[index]["func_sem"]
                        )
                        cnt_pat_syn = 0
                        for idx in pat_syn:
                            for idx_tgt in sus_method_syn:
                                if pat_syn[idx] == sus_method_syn[idx_tgt]:
                                    del sus_method_syn[idx_tgt]
                                    cnt_pat_syn += 1
                                    break

                        if (
                            len(set(pat_syn)) > 0
                            and cnt_pat_syn / len(pat_syn) > th_syn_p
                        ):
                            is_match = False
                            ans_list[filename][CVE][key][method_name]["pat_syn"] = (
                                is_match
                            )
                        else:
                            ans_list[filename][CVE][key][method_name]["pat_syn"] = True

                        cnt_match_pat_sem = 0
                        for idx in pat_sem:
                            three_tuple_pat_sem = pat_sem[idx]
                            for idx_tgt in sus_method_sem:
                                if three_tuple_pat_sem == sus_method_sem[idx_tgt]:
                                    del sus_method_sem[idx_tgt]
                                    cnt_match_pat_sem += 1
                                    break
                        if (
                            len(pat_sem) > 0
                            and cnt_match_pat_sem / len(pat_sem) > th_sem_p
                        ):
                            is_match = False
                            ans_list[filename][CVE][key][method_name]["pat_sem"] = False
                        else:
                            ans_list[filename][CVE][key][method_name]["pat_sem"] = True

                elif key.startswith("del__split__"):
                    syn_sig = sig[key]["syn"]
                    sem_sig = sig[key]["sem"]
                    split_list = key.split("__split__")
                    if len(sem_sig) == 0:
                        continue

                    match_dict[split_list[1] + "__split__" + split_list[2]] = []
                    for index in sus_method_dict:
                        sus_method_syn = copy.deepcopy(
                            sus_method_dict[index]["func_syn"]
                        )
                        sus_method_sem = copy.deepcopy(
                            sus_method_dict[index]["func_sem"]
                        )
                        method_name = sus_method_dict[index]["method_name"]
                        filename = tmp_tar_file[sus_method_dict[index]["file_name"]]
                        is_match = True
                        if filename not in ans_list.keys():
                            ans_list[filename] = {}
                        if CVE not in ans_list[filename].keys():
                            ans_list[filename][CVE] = {}
                        if key not in ans_list[filename][CVE].keys():
                            ans_list[filename][CVE][key] = {}
                        if method_name not in ans_list[filename][CVE][key].keys():
                            ans_list[filename][CVE][key][method_name] = {}
                        ans_list[filename][CVE][key][method_name]["line_number"] = (
                            sus_method_dict[index]["line_number"]
                        )
                        is_match = True
                        cnt_vul_syn = 0
                        for syn in syn_sig:
                            tar_key = -1
                            for syn_key in sus_method_syn:
                                if syn == sus_method_syn[syn_key]:
                                    tar_key = syn_key
                                    break
                            if tar_key != -1:
                                del sus_method_syn[tar_key]
                                cnt_vul_syn += 1

                        if (
                            len(set(syn_sig)) > 0
                            and cnt_vul_syn / len(syn_sig) <= th_syn_v
                        ):
                            is_match = False
                            ans_list[filename][CVE][key][method_name]["syn"] = False
                        else:
                            ans_list[filename][CVE][key][method_name]["syn"] = True

                        cnt_match_vul_sem = 0
                        for three_tuple_pat_sem in sem_sig:
                            tar_key = -1
                            for syn_key in sus_method_sem:
                                if three_tuple_pat_sem == sus_method_sem[syn_key]:
                                    tar_key = syn_key
                                    break
                            if tar_key != -1:
                                del sus_method_sem[tar_key]
                                cnt_match_vul_sem += 1
                        if (
                            len(sem_sig) != 0
                            and cnt_match_vul_sem / len(sem_sig) <= th_syn_v
                        ):
                            is_match = False
                            ans_list[filename][CVE][key][method_name]["sem"] = is_match
                        else:
                            ans_list[filename][CVE][key][method_name]["sem"] = True
    if not os.path.exists(f"./ansList"):
        os.system(f"mkdir ./ansList")
    fileName = file.replace(" ", "_").replace("/", "_")
    with open(f"./ansList/{fileName}.json", "w") as f:
        json.dump(ans_list, f)

    os.system(f"rm -r {work_dir}normalized_{worker_id}")
    os.system(f"rm -r {tempSignature}{worker_id}")
    os.system(f"rm -r {work_dir}normalizeJson_{worker_id}")
    os.system(f"rm -r {work_dir}slicingJson_{worker_id}")
    return ans_list


def getSimiliarFiles(repoDir, strict, work_dir, sess):
    time0 = time.time()
    repoName = repoDir.split("/")[-1]

    logger = logging.getLogger(repoName)
    logger.setLevel(logging.DEBUG)

    os.chdir(originalDir)
    open("./detectLog/{0}.log".format(repoName), "w").close()
    file_handler = logging.FileHandler("./detectLog/{0}.log".format(repoName))
    file_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    worker_id = sess.worker_id.replace("/", "_")
    if not os.path.exists(f"{work_dir}/temp_" + worker_id):
        os.system(f"mkdir {work_dir}/temp_" + worker_id)
    if not os.path.exists(f"{work_dir}/normalized_" + worker_id):
        os.system(f"mkdir {work_dir}/normalized_" + worker_id)
    CVE_dict_line_number = {}
    file_hash_line_number_to_index_dict = {}
    lock.acquire()
    os.system("cp -r " + "./vulFile " + repoDir)
    os.chdir("./saga")
    os.system("rm -r ./logs")
    os.system("rm -r ./result")
    os.system("rm -r ./tokenData")
    if os.path.exists(f"{repoDir}/sig_origin"):
        os.system(f"rm -r {repoDir}/sig_origin")
    cmd = "java -jar ./SAGACloneDetector-small.jar " + repoDir
    out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode(
        "utf-8", errors="replace"
    )
    logger.info(out)
    fileIndex = {}
    with open("./result/MeasureIndex.csv", "r") as f:
        lines = f.readlines()
        for line in lines:
            id = line.split(",")[0]
            fileName = line.split(",")[1]
            endLine = line.split(",")[-1]
            fileIndex[id] = fileName
            if "vulFile" in fileName:
                file_hash = fileName.split("/")[-1]
                file_hash_line_number_to_index_dict[
                    file_hash + "__split__" + endLine.strip()
                ] = id

    for CVE in CVE_dict.keys():
        CVE_dict_line_number[CVE] = []
        for ele in CVE_dict[CVE].keys():
            for name in CVE_dict[CVE][ele].keys():
                if (
                    CVE_dict[CVE][ele][name]["lineEnd"]
                    - CVE_dict[CVE][ele][name]["lineStart"]
                    <= 2
                ):
                    continue
                if (
                    ele + "__split__" + str(CVE_dict[CVE][ele][name]["lineEnd"])
                    in file_hash_line_number_to_index_dict.keys()
                ):
                    CVE_dict_line_number[CVE].append(
                        file_hash_line_number_to_index_dict[
                            ele + "__split__" + str(CVE_dict[CVE][ele][name]["lineEnd"])
                        ]
                    )
    zero_CVE_set = set()
    for CVE in CVE_dict_line_number.keys():
        if len(CVE_dict_line_number[CVE]) == 0:
            zero_CVE_set.add(CVE)
    for CVE in zero_CVE_set:
        del CVE_dict_line_number[CVE]
    clone_dict = {}
    logger.info(os.getcwd())
    with open("./result/type12_snippet_result.csv", "r", encoding="utf8") as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            temp = i
            while temp < len(lines) and lines[temp] != "\n":
                temp += 1
            repo_set = set()
            clone_set = set()
            for cur in range(i, temp):
                file_name = fileIndex[lines[cur].split(",")[1]]
                if "vulFile" in file_name:
                    clone_set.add(lines[cur].split(",")[1])
                else:
                    repo_set.add(lines[cur].split(",")[1])

            for id in clone_set:
                if id not in clone_dict.keys():
                    clone_dict[id] = set()
                for repo_id in repo_set:
                    clone_dict[id].add(repo_id)
            i = temp + 1
    i = 0
    with open("./result/type3_snippet_result.csv", "r", encoding="utf8") as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            temp = i
            while temp < len(lines) and lines[temp] != "\n":
                temp += 1
            repo_set = set()
            clone_set = set()
            for cur in range(i, temp):
                file_name = fileIndex[lines[cur].split(",")[1]]
                if "vulFile" in file_name:
                    clone_set.add(lines[cur].split(",")[1])
                else:
                    repo_set.add(lines[cur].split(",")[1])
            for id in clone_set:
                if id not in clone_dict.keys():
                    clone_dict[id] = set()
                for repo_id in repo_set:
                    clone_dict[id].add(repo_id)
            i = temp + 1
    filtered_dict = dict()
    filtered_file_set = set()
    for cve in CVE_dict_line_number.keys():
        file_set = set()
        for id in CVE_dict_line_number[cve]:
            if id in clone_dict.keys():
                for clone_id in clone_dict[id]:
                    file_name = fileIndex[clone_id]
                    if "vulFile" not in file_name:
                        file_set.add(file_name)
                        filtered_file_set.add(file_name)
        if len(file_set) != 0:
            filtered_dict[cve] = file_set
    lock.release()

    total_index_to_method_dict = {}
    logger.info(len(filtered_file_set))
    cnt = 0
    for file in filtered_file_set:
        logger.info(file)
        index_to_method_dict = generate_signature_in_file(
            repoDir, file, cnt, work_dir, sess, logger
        )
        if index_to_method_dict is None:
            continue
        cnt += len(index_to_method_dict)
        for index in index_to_method_dict:
            total_index_to_method_dict[index] = index_to_method_dict[index]

    sus_method_dict = {}
    for index in total_index_to_method_dict.keys():
        with open(
            "./tempSignature_" + worker_id.__str__() + "/" + index.__str__() + ".json",
            "r",
        ) as f:
            sus_method_dict[index] = json.load(f)

    for CVE in filtered_dict:
        sig = CVE_sigs[CVE]
        match_dict = {}
        for key in sig.keys():
            if key.count("__split__") <= 1 and not (
                key.startswith("del__split__") or key.startswith("add__split__")
            ):
                logger.info(CVE + " " + key)
                delete_lines = sig[key]["deleteLines"]
                vul_syn = sig[key]["vul_syn"]
                vul_sem = sig[key]["vul_sem"]
                pat_syn = sig[key]["pat_syn"]
                pat_sem = sig[key]["pat_sem"]
                split_list = key.split("__split__")

                match_dict[CVE + "__split__" + split_list[0]] = []
                for index in sus_method_dict:
                    sus_method_syn = copy.deepcopy(sus_method_dict[index]["func_syn"])
                    sus_method_sem = copy.deepcopy(sus_method_dict[index]["func_sem"])
                    method = total_index_to_method_dict[index]["method_name"]
                    logger.info(str(index) + method)
                    is_match = True

                    for line in delete_lines:
                        if line not in sus_method_syn:
                            is_match = False
                        else:
                            sus_method_syn.remove(line)
                    sus_method_syn = copy.deepcopy(sus_method_dict[index]["func_syn"])
                    sus_method_sem = copy.deepcopy(sus_method_dict[index]["func_sem"])
                    cnt_vul_syn = 0
                    for syn in vul_syn:
                        if syn in sus_method_syn:
                            sus_method_syn.remove(syn)
                            cnt_vul_syn += 1
                    if len(set(vul_syn)) > 0:
                        logger.info(cnt_vul_syn / len(vul_syn))
                        logger.info(is_match)
                    if len(set(vul_syn)) > 0 and cnt_vul_syn / len(vul_syn) <= th_syn_v:
                        is_match = False

                    cnt_match_vul_sem = 0
                    for three_tuple_vul_sem in vul_sem:
                        if three_tuple_vul_sem in sus_method_sem:
                            sus_method_sem.remove(three_tuple_vul_sem)
                            cnt_match_vul_sem += 1
                    if len(vul_sem) > 0:
                        logger.info(cnt_match_vul_sem / len(vul_sem))
                        logger.info(is_match)
                    if (
                        len(vul_sem) != 0
                        and cnt_match_vul_sem / len(vul_sem) <= th_sem_v
                    ):
                        is_match = False

                    if strict:
                        sus_method_syn = copy.deepcopy(
                            sus_method_dict[index]["func_syn"]
                        )
                        sus_method_sem = copy.deepcopy(
                            sus_method_dict[index]["func_sem"]
                        )
                        cnt_pat_syn = 0
                        for syn in pat_syn:
                            if syn in sus_method_syn:
                                sus_method_syn.remove(syn)
                                cnt_pat_syn += 1
                        if len(set(pat_syn)) > 0:
                            logger.info(cnt_pat_syn / len(pat_syn))
                            logger.info(is_match)
                        if (
                            len(set(pat_syn)) > 0
                            and cnt_pat_syn / len(pat_syn) > th_syn_p
                        ):
                            is_match = False

                        cnt_match_pat_sem = 0
                        for three_tuple_pat_sem in pat_sem:
                            if three_tuple_pat_sem in sus_method_sem:
                                sus_method_sem.remove(three_tuple_pat_sem)
                                cnt_match_pat_sem += 1
                        if len(pat_sem) > 0:
                            logger.info(cnt_match_pat_sem / len(pat_sem))
                            logger.info(is_match)
                        if (
                            len(pat_sem) > 0
                            and cnt_match_pat_sem / len(pat_sem) > th_sem_p
                        ):
                            is_match = False
                    if is_match:
                        match_dict[CVE + "__split__" + split_list[0]].append(index)
            elif key.startswith("del__split__"):
                syn_sig = sig[key]["syn"]
                sem_sig = sig[key]["sem"]
                if len(sem_sig) == 0:
                    continue
                split_list = key.split("__split__")

                match_dict[CVE + "__split__" + split_list[1]] = []
                for index in sus_method_dict:
                    sus_method_syn = copy.deepcopy(sus_method_dict[index]["func_syn"])
                    sus_method_sem = copy.deepcopy(sus_method_dict[index]["func_sem"])
                    is_match = True

                    cnt_vul_syn = 0
                    for syn in syn_sig:
                        if syn in sus_method_syn:
                            sus_method_syn.remove(syn)
                            cnt_vul_syn += 1
                    if len(set(syn_sig)) > 0:
                        logger.info(cnt_vul_syn / len(syn_sig))

                    if len(set(syn_sig)) > 0 and cnt_vul_syn / len(syn_sig) <= 0.7:
                        is_match = False

                    cnt_match_vul_sem = 0
                    for three_tuple_pat_sem in sem_sig:
                        if three_tuple_pat_sem in sus_method_sem:
                            sus_method_sem.remove(three_tuple_pat_sem)
                            cnt_match_vul_sem += 1
                    if len(sem_sig) != 0 and cnt_match_vul_sem / len(sem_sig) <= 0.7:
                        logger.info("not match sem")
                        is_match = False
                    if is_match:
                        match_dict[CVE + "__split__" + split_list[1]].append(index)
        CVE_is_match = False
        for key in match_dict.keys():
            if len(match_dict[key]) != 0:
                CVE_is_match = True
                break
        if CVE_is_match:
            with open("results_empirical.txt", "a", encoding="utf8") as f:
                f.write("Found " + CVE + " in " + repoDir + "!\n")
                logger.info("Found " + CVE + " in " + repoDir + "!\n")
                for key in match_dict.keys():
                    f.write("Method " + key + " matches the following methods:\n")
                    logger.info("Method " + key + " matches the following methods:\n")
                    for id in match_dict[key]:
                        method_info = total_index_to_method_dict[id]
                        f.write(
                            "Method "
                            + method_info["method_name"]
                            + " in file "
                            + method_info["file_name"]
                            + " at line "
                            + method_info["line_number"]
                            + ".\n"
                        )
                        logger.info(
                            "Method "
                            + method_info["method_name"]
                            + " in file "
                            + method_info["file_name"]
                            + " at line "
                            + method_info["line_number"]
                            + ".\n"
                        )
                f.write("\n")

    os.system(f"rm -r {repoDir}/vulFile/")
    time1 = time.time()
    logger.info("Elapsed time:{0} to detect {1}".format(str(time1 - time0), repoDir))
    os.system(f"rm {work_dir}/temp_{worker_id}/*")
    os.system(f"rm {work_dir}/normalized_{worker_id}/*")
    os.system(f"rm ./tempSignature_{worker_id}/*")


def dfmp(
    df,
    CVEList,
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
    it = _dfmp(function, items, CVEList, ordr, workers, cs, desc, total)
    if generator:
        return it
    else:
        processed = []
        processed.extend(it)
        return processed


def _dfmp(function, items, CVEList, ordr, workers, cs, desc, total):
    if desc is not None:
        desc = f"({workers} Workers) {desc}"
    with Pool(processes=workers) as p:
        map_func = getattr(p, "imap" if ordr else "imap_unordered")
        it = map_func(functools.partial(function, CVEList), items, cs)
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


def preprocess(row, fn, CVEList, sess):
    detect_dir, file = row["detect_dir"], row["dirs"]
    fn(detect_dir, file, CVEList, sess)


def preprocess_whole_df_split(CVEList, t):
    """
    preprocess one split of the dataframe
    """

    i, split = t
    with open(f"./hpc/logs/detect_output_{i}.joernlog", "wb") as lf:
        sess = joern_session.JoernSession(f"detect/{i}", logfile=lf, clean=True)
        try:
            fn = functools.partial(
                detect_dirs,
            )
            items = split.to_dict("records")
            position = 0 if not isinstance(i, int) else int(i)
            for row in tqdm(items, desc=f"(worker {i})", position=position):
                preprocess(row, fn, CVEList, sess)
        finally:
            sess.close()


if __name__ == "__main__":
    detecteds = []
    needRerun = []
    cnt = 0
    for detected in os.listdir("./detectLog"):
        if detected.replace(".log", "") in detecteds:
            continue
        f = open("./detectLog/" + detected)
        lines = f.readlines()
        j = len(lines) - 1
        cnt += 1
        while j >= 0 and lines[j] == "\n":
            j -= 1
        if j >= 0 and "Elapsed time:" in lines[j]:
            detecteds.append(detected.replace(".log", ""))
    with open("done_1.json", "w") as f:
        json.dump(detecteds, f)
    df = pd.read_csv("targetList.csv")
    notRun = []
    already_run = []
    no_cpg = []
    for i, row in df.iterrows():
        if row["detect_dir"].split("/")[-1] not in detecteds:
            notRun.append(row.to_dict())
    print(f"there is {len(notRun)} need to run")
    df_need_run = pd.DataFrame(notRun)
    workers = 1
    if workers == 1:
        preprocess_whole_df_split(("all", df_need_run))
    else:
        splits = np.array_split(df_need_run, workers)
        dfmp(
            enumerate(splits),
            preprocess_whole_df_split,
            ordr=False,
            workers=workers,
            cs=1,
        )
    time1 = time.time()
    print("Elapsed time:{0}".format(str(time1 - time0)))
