import json
import os

import cpu_heater
import pandas as pd
from extract_single_method import get_method_code
from tqdm import tqdm


def work_entract_fn(detect_loc, data):
    target_file_method = {}
    target_file_method[data["CVE"]] = {}
    error = set()
    for loc in detect_loc:
        if "https:" in loc:
            try:
                origin_method = loc.split("#####")[1]
                repo = data["target_repo"].replace("@@", "/")
                target_file = loc.split("#####")[0].replace(
                    f"https://github.com/{repo}/blob/{data['target_tag']}/", ""
                )
                if "test/" in target_file or "tests/" in target_file:
                    continue
                target_method = loc.split("#####")[2]
                if target_method == "MACRO" or target_method == "VARIABLE":
                    continue
                if origin_method == "":
                    origin_method = target_method
                if "./target_repo_cache" not in target_file:
                    if target_file.startswith("/"):
                        target_file = target_file.strip()[1:]
                    target_file = os.path.join(
                        "./target_repo_cache",
                        data["target_repo"]
                        + "-"
                        + data["target_tag"].replace("/", "_"),
                        target_file.replace(" ", ""),
                    )

                if "vulFile" in target_file:
                    continue
                key = f"{data['CVE']}##{data['target_repo']}##{data['target_tag']}##{target_method}##{origin_method}"

                if key in target_file_method[data["CVE"]]:
                    continue

                key = key.replace(" ", "")
                target_func_code = get_method_code(target_file, target_method, key)
                if target_func_code == "":
                    error.add(data["CVE"])
                    continue
                target_file_method[data["CVE"]][key] = target_func_code
            except Exception as e:
                print(key)
                error.add(data["CVE"])
                print(e)
    return target_file_method, error


def sim_between_target_origin():
    worker_list = []

    df = pd.read_excel("../dataset/groundtruth.xlsx")
    csv_data = df.to_dict(orient="records")

    target_file_methods = {}
    error = set()
    cnt = 0
    for data in tqdm(csv_data):
        detect_loc = data["detect_loc"].split("\n")
        worker_list.append((detect_loc, data))
    results = cpu_heater.multiprocess(work_entract_fn, worker_list, show_progress=True)

    for result in results:
        target_file_method, e = result
        error.update(e)
        for cve in target_file_method:
            if cve not in target_file_methods:
                target_file_methods[cve] = target_file_method[cve]
            else:
                target_file_methods[cve].update(target_file_method[cve])

    fp = open("target_code.json", "w")
    json.dump(target_file_methods, fp, indent=4)
    fp.close()

    os.system("rm *.c")
    os.system("rm *.cpp")
    os.system("rm *.h")
    os.system("rm *.cc")
    os.system("rm *.cxx")


def extract_affected_version_fn(cve, filename, key, origin_method):
    errors = set()
    target_code = {}
    target_code[cve] = {}
    try:
        method_code = get_method_code(filename, origin_method, key)
        target_code[cve][key] = method_code
    except Exception as e:
        print(e)
        errors.add(key)

    return target_code, errors


def extract_affected_version():
    fp = open("datas/affected.json")
    affected_version = json.load(fp)
    fp.close()

    fp = open("transfer_code.json")
    target_code = json.load(fp)
    fp.close()

    fp = open("./cve_origin_code.json")
    cve_method = json.load(fp)
    fp.close()

    errors = set()
    worker_list = set()

    for cve in tqdm(affected_version):
        if cve not in cve_method:
            continue
        if cve not in target_code:
            target_code[cve] = {}

        for method in cve_method[cve]["patch"]:
            origin_method = method.split("#")[1]
            origin_file = method.split("#")[0]
            for tag in affected_version[cve]["affected"]:
                key = f"{cve}##{affected_version[cve]['repo']}##{tag}##{origin_method}##{origin_method}"
                if key in target_code[cve]:
                    continue
                filename = f"./target_repo_cache/{affected_version[cve]['repo']}-{tag.replace('/','_')}/{origin_file}"
                if "test/" in filename or "tests/" in filename:
                    continue
                if os.path.exists(filename):
                    worker_list.add((cve, filename, key, origin_method))

    results = cpu_heater.multiprocess(
        extract_affected_version_fn, list(worker_list), show_progress=True
    )

    for r in results:
        res, error = r
        for e in error:
            print(e)
            errors.add(error)
        for cve in res:
            for key in res[cve]:
                target_code[cve][key] = res[cve][key]

    os.system("rm *.c")
    os.system("rm *.cpp")
    os.system("rm *.h")
    os.system("rm *.cc")
    os.system("rm *.cxx")
    fp = open("target_code_w_o_testcase.json", "w")
    json.dump(target_code, fp, indent=4)
    fp.close()


if __name__ == "__main__":
    extract_affected_version()
