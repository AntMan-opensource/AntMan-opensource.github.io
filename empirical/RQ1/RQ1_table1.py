import json
import os
import sys

import cpu_heater
import pandas as pd
import tools.parseutility as parser
from tqdm import tqdm

import format_code


def exact_match(a: str, b: str) -> bool:
    if a == b:
        return True
    a = format_code.normalize(a, del_comments=True)
    b = format_code.normalize(b, del_comments=True)
    return a == b


def abstract(body, filename, ext):
    global delimiter

    tempFile = filename.replace("/", "_") + "." + ext
    ftemp = open(tempFile, "w", encoding="UTF-8")
    ftemp.write(body)
    ftemp.close()

    functionInstanceList = parser.parseFile_deep(tempFile, "")
    abstractBody = ""

    for functionInstance in functionInstanceList:
        originalFunctionBody, abstractBody = parser.abstract(functionInstance, 4)

    os.remove(tempFile)
    return abstractBody


def worker_fn(transfer_func, dataset, transfer_code, cve, cve_method):
    origin_diff_method_type_1 = set()
    origin_diff_method_type_2 = set()
    origin_diff_method_type_34 = set()

    transfer_diff_method_type_1 = set()
    transfer_diff_method_type_2 = set()
    transfer_diff_method_type_34 = set()

    origin_method = transfer_func.split("##")[-1].replace(" ", "")
    transfer_proj = transfer_func.split("##")[1]
    origin_proj = (
        dataset[cve]["repo"].replace("https://github.com/", "").replace("/", "@@")
    )
    origin_code = ""
    if origin_method != "":
        transfer_codes = transfer_code[cve][transfer_func]
        origin_codes = set()
        type1 = False
        for method in cve_method[cve]["patch"]:
            if origin_method.lower() == method.split("#")[1].lower():
                origin_codes.add(cve_method[cve]["patch"][method]["before_func_code"])
            elif method.split("#")[1].lower() in origin_method.lower():
                origin_codes.add(cve_method[cve]["patch"][method]["before_func_code"])
        transfer_codes = transfer_code[cve][transfer_func]

        true_origin_code = ""
        for origin_code in origin_codes:
            if exact_match(
                "\n".join(origin_code.split("\n")[1:]),
                "\n".join(transfer_codes.split("\n")[1:]),
            ):
                type1 = True
                true_origin_code = origin_code
                break
            elif (
                exact_match(
                    "\n".join(
                        abstract(origin_code, transfer_func, "c").split("\n")[1:]
                    ),
                    "\n".join(
                        abstract(transfer_codes, transfer_func, "c").split("\n")[1:]
                    ),
                )
                or transfer_codes == ""
            ):
                true_origin_code = origin_code
        if type1:
            if origin_proj == transfer_proj:
                origin_diff_method_type_1.add(transfer_func)
            else:
                transfer_diff_method_type_1.add(transfer_func)
        elif true_origin_code != "" or transfer_codes == "":
            if origin_proj == transfer_proj:
                origin_diff_method_type_2.add(transfer_func)
            else:
                transfer_diff_method_type_2.add(transfer_func)

        else:
            if origin_proj == transfer_proj:
                origin_diff_method_type_34.add(transfer_func)
                fp = open("origin.c", "w")
                fp.write(origin_code)
                fp.close()

                fp = open("transfer.c", "w")
                fp.write(transfer_codes)
                fp.close()
            else:
                transfer_diff_method_type_34.add(transfer_func)
    else:
        print(cve)

    return (
        origin_diff_method_type_1,
        transfer_diff_method_type_1,
        origin_diff_method_type_2,
        transfer_diff_method_type_2,
        origin_diff_method_type_34,
        transfer_diff_method_type_34,
    )


def sim_transfer_origin_calc_func_level():
    fp = open("./datas/transfer_code.json")
    transfer_code = json.load(fp)
    fp.close()

    fp = open("./datas/cve_origin_code.json")
    cve_method = json.load(fp)
    fp.close()

    fp = open("../dataset/emperical_cve_list.json")
    dataset = json.load(fp)
    fp.close()

    origin_diff_method_type_1 = set()
    origin_diff_method_type_2 = set()
    origin_diff_method_type_34 = set()

    transfer_diff_method_type_1 = set()
    transfer_diff_method_type_2 = set()
    transfer_diff_method_type_34 = set()

    errors = set()
    worker_list = []

    for cve in tqdm(transfer_code):
        if cve not in cve_method:
            errors.add(cve)
            continue
        if cve not in dataset:
            continue
        for transfer_func in transfer_code[cve]:
            worker_list.append((transfer_func, dataset, transfer_code, cve, cve_method))

    results = cpu_heater.multithreads(worker_fn, list(worker_list), show_progress=True)
    for res in results:
        (
            origin_diff_method_type_1_t,
            transfer_diff_method_type_1_t,
            origin_diff_method_type_2_t,
            transfer_diff_method_type_2_t,
            origin_diff_method_type_34_t,
            transfer_diff_method_type_34_t,
        ) = res
        origin_diff_method_type_1.update(origin_diff_method_type_1_t)
        transfer_diff_method_type_1.update(transfer_diff_method_type_1_t)
        origin_diff_method_type_2.update(origin_diff_method_type_2_t)
        transfer_diff_method_type_2.update(transfer_diff_method_type_2_t)
        origin_diff_method_type_34.update(origin_diff_method_type_34_t)
        transfer_diff_method_type_34.update(transfer_diff_method_type_34_t)

    method_info = {
        "origin": {
            "type1": list(origin_diff_method_type_1),
            "type2": list(origin_diff_method_type_2),
            "type34": list(origin_diff_method_type_34),
        },
        "transfer": {
            "type1": list(transfer_diff_method_type_1),
            "type2": list(transfer_diff_method_type_2),
            "type34": list(transfer_diff_method_type_34),
        },
    }

    fp = open("datas/Patch_Granularity.json", "w")
    json.dump(method_info, fp, indent=4)
    fp.close()


def get_results_RQ1():
    fp = open("./datas/Patch_Granularity.json")
    Patch_Granularity = json.load(fp)
    fp.close()

    fp = open("./datas/patch_info.json")
    patch_info = json.load(fp)
    fp.close()

    patch_result_info = {}
    results = {}
    for key in Patch_Granularity:
        patch_result_info[key] = {}
        for type in Patch_Granularity[key]:
            for info in Patch_Granularity[key][type]:
                cve = info.split("##")[0]
                repo = info.split("##")[1]
                version = info.split("##")[2]
                if f"{cve}##{repo}##{version}" not in patch_result_info[key]:
                    patch_result_info[key][f"{cve}##{repo}##{version}"] = {}

                patch_result_info[key][f"{cve}##{repo}##{version}"][
                    info.replace(f"{cve}##{repo}##{version}##", "")
                ] = type

    positives = set()

    df = pd.read_excel("../dataset/groundtruth.xlsx")
    csv_data = df.to_dict(orient="records")
    all_results = {}
    tool_set = {"VUDDY", "MVP", "V1SCAN", "MOVERY", "FIRE"}
    for tool in tool_set:
        all_results[tool] = {}

    for data in csv_data:
        if str(data["detect_loc"]) == "nan":
            key = f"{data['CVE']}##{data['transfer_repo']}##{data['transfer_tag']}"
            if str(data["TP/FP"]) == "TP":
                positives.add(
                    f"{data['CVE']}##{data['transfer_repo']}##{data['transfer_tag']}"
                )
                for t in tool_set:
                    all_results[t][key] = "FN"
        else:
            detect_loc = data["detect_loc"].split("\n")
            i = 0
            while i < len(detect_loc):
                loc = detect_loc[i]
                if loc.strip() == "all" or loc.strip() == "":
                    i += 1
                    continue
                if "https:" not in loc:
                    tool = loc.strip().replace(":", "")
                    if tool == "ht":
                        i += 1
                        continue
                    i += 1
                    if i < len(detect_loc):
                        loc = detect_loc[i]
                    while i < len(detect_loc) and "https:" in loc:
                        if len(loc.split("#####")) < 3:
                            i += 1
                            if i < len(detect_loc):
                                loc = detect_loc[i]
                            continue
                        origin_method = loc.split("#####")[1]
                        repo = data["transfer_repo"].replace("@@", "/")
                        transfer_file = loc.split("#####")[0].replace(
                            f"https://github.com/{repo}/blob/{data['transfer_tag']}/",
                            "",
                        )
                        transfer_method = loc.split("#####")[2]
                        if transfer_method == "MACRO" or transfer_method == "VARIABLE":
                            i += 1
                            if i < len(detect_loc):
                                loc = detect_loc[i]
                            continue
                        if origin_method == "":
                            origin_method = transfer_method
                        if "./transfer_repo_cache" not in transfer_file:
                            if transfer_file.startswith("/"):
                                transfer_file = transfer_file.strip()[1:]
                            transfer_file = os.path.join(
                                "./transfer_repo_cache",
                                data["transfer_repo"]
                                + "-"
                                + data["transfer_tag"].replace("/", "_"),
                                transfer_file.replace(" ", ""),
                            )

                        key = f"{data['CVE']}##{data['transfer_repo']}##{data['transfer_tag']}"
                        if str(data["TP/FP"]) == "TP":
                            positives.add(
                                f"{data['CVE']}##{data['transfer_repo']}##{data['transfer_tag']}"
                            )
                            for t in tool_set:
                                if t != tool and key not in all_results[tool]:
                                    all_results[t][key] = "FN"

                        all_results[tool][key] = data["TP/FP"]
                        i += 1

                        if i < len(detect_loc):
                            loc = detect_loc[i]
                else:
                    i += 1
                    if i < len(detect_loc):
                        loc = detect_loc[i]

    fp = open("datas/affected.json")
    affected_version = json.load(fp)
    fp.close()

    fp = open("./datas/cve_origin_code.json")
    cve_method = json.load(fp)
    fp.close()

    fp = open("../dataset/emperical_cve_list.json")
    cve_list = json.load(fp)
    fp.close()
    for cve in tqdm(affected_version):
        if cve not in cve_list:
            continue
        if cve not in cve_method:
            continue
        if "linux" in affected_version[cve]["repo"]:
            continue
        for method in cve_method[cve]["patch"]:
            origin_method = method.split("#")[1]
            for tag in affected_version[cve]["affected"]:
                key = f"{cve}##{affected_version[cve]['repo']}##{tag}"
                for tool in all_results:
                    if key not in all_results[tool]:
                        all_results[tool][key] = "FN"
                positives.add(key)

    all_cves_feature = {}
    result_feature = {}
    for key in patch_result_info:
        results[key] = {}
        all_cves_feature[key] = {}
        for origin_transfer_pair in patch_result_info[key]:
            if origin_transfer_pair not in positives:
                continue
            cve = origin_transfer_pair.split("##")[0]
            if patch_info[cve]["method_num"] > 1:
                if "M." not in results[key]:
                    results[key]["M."] = {}
                    all_cves_feature[key]["M."] = {}
                type34 = False
                type2 = False
                for info in patch_result_info[key][origin_transfer_pair]:
                    if patch_result_info[key][origin_transfer_pair][info] == "type34":
                        type34 = True
                    elif patch_result_info[key][origin_transfer_pair][info] == "type2":
                        type2 = True

                if type34:
                    result_feature[f"{origin_transfer_pair}"] = (
                        f"{key}__split__type34__split__M"
                    )
                    try:
                        all_cves_feature[key]["M."]["type34"].append(cve)
                        results[key]["M."]["type34"] += 1
                    except:
                        results[key]["M."]["type34"] = 1
                        all_cves_feature[key]["M."]["type34"] = [cve]
                elif type2:
                    result_feature[f"{origin_transfer_pair}"] = (
                        f"{key}__split__type2__split__M"
                    )
                    try:
                        all_cves_feature[key]["M."]["type2"].append(cve)
                        results[key]["M."]["type2"] += 1
                    except:
                        results[key]["M."]["type2"] = 1
                        all_cves_feature[key]["M."]["type2"] = [cve]
                else:
                    result_feature[f"{origin_transfer_pair}"] = (
                        f"{key}__split__type1__split__M"
                    )
                    try:
                        all_cves_feature[key]["M."]["type1"].append(cve)
                        results[key]["M."]["type1"] += 1
                    except:
                        results[key]["M."]["type1"] = 1
                        all_cves_feature[key]["M."]["type1"] = [cve]
            else:
                if "S." not in results[key]:
                    results[key]["S."] = {}
                    all_cves_feature[key]["S."] = {}
                type34 = False
                type2 = False
                for info in patch_result_info[key][origin_transfer_pair]:
                    if patch_result_info[key][origin_transfer_pair][info] == "type34":
                        type34 = True
                    elif patch_result_info[key][origin_transfer_pair][info] == "type2":
                        type2 = True

                if type34:
                    result_feature[f"{origin_transfer_pair}"] = (
                        f"{key}__split__type34__split__S"
                    )
                    try:
                        all_cves_feature[key]["S."]["type34"].append(cve)
                        results[key]["S."]["type34"] += 1
                    except:
                        results[key]["S."]["type34"] = 1
                        all_cves_feature[key]["S."]["type34"] = [cve]
                elif type2:
                    result_feature[f"{origin_transfer_pair}"] = (
                        f"{key}__split__type2__split__S"
                    )
                    try:
                        all_cves_feature[key]["S."]["type2"].append(cve)
                        results[key]["S."]["type2"] += 1
                    except:
                        results[key]["S."]["type2"] = 1
                        all_cves_feature[key]["S."]["type2"] = [cve]
                else:
                    result_feature[f"{origin_transfer_pair}"] = (
                        f"{key}__split__type1__split__S"
                    )
                    try:
                        all_cves_feature[key]["S."]["type1"].append(cve)
                        results[key]["S."]["type1"] += 1
                    except:
                        results[key]["S."]["type1"] = 1
                        all_cves_feature[key]["S."]["type1"] = [cve]

    fp = open("datas/all_results.json", "w")
    json.dump(all_results, fp, indent=4)
    fp.close()

    fp = open("datas/all_cves_feature.json", "w")
    json.dump(all_cves_feature, fp, indent=4)
    fp.close()

    fp = open("datas/patch_result_info.json", "w")
    json.dump(patch_result_info, fp, indent=4)
    fp.close()

    fp = open("datas/results_RQ1.json", "w")
    json.dump(results, fp, indent=4)
    fp.close()

    fp = open("result_feature.json", "w")
    json.dump(result_feature, fp, indent=4)
    fp.close()


if __name__ == "__main__":
    sim_transfer_origin_calc_func_level()
    get_results_RQ1()
