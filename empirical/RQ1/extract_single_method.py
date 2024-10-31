import json
import os
import re
import subprocess
import sys

from tqdm import tqdm

import format_code
from config import CTAGS_PATH


def get_method_code(filename, method_name, key=""):
    fp = open(filename, errors="ignore")
    codes = fp.read()
    fp.close()

    fmc = format_code.format_and_del_comment_c_cpp(codes)

    if key == "":
        filepath = method_name + filename.replace("/", "_").replace(" ", "")
    else:
        filepath = (
            key.replace("/", "_") + "." + filename.split(".")[-1].replace(" ", "")
        )

    fp = open(filepath, "w")
    fp.write(fmc)
    fp.close()
    number = re.compile(r"(\d+)")

    finding_cfiles = subprocess.check_output(
        CTAGS_PATH + ' -f - --kinds-C=* --fields=neKSt "' + filepath + '"',
        stderr=subprocess.STDOUT,
        shell=True,
    ).decode(errors="ignore")
    alllist = str(finding_cfiles)

    method_code = ""

    for result in alllist.split("\n"):
        if result == "" or result == " " or result == "\n":
            continue
        if len(result.split("\t")) < 7:
            continue

        funcname = result.split("\t")[0]
        print(funcname, method_name)

        if (
            result.split("\t")[3] == "f"
            and "function:" not in result.split("\t")[5]
            and "function:" not in result.split("\t")[6]
            and "end:" in result.split("\t")[-1]
        ):
            startline = int(result.split("\t")[4].replace("line:", ""))
            endline = int(result.split("\t")[-1].replace("end:", ""))
            if funcname.replace(" ", "") == method_name.replace(" ", ""):
                method_code = "\n".join(fmc.split("\n")[startline - 1 : endline])
                break
        elif "function" in result.split("\t"):
            elemList = result.split("\t")
            j = elemList.index("function")
            startline = -1
            endline = -1
            while j < len(elemList):
                elem = elemList[j]
                if "line:" in elem and number.search(elem) is not None:
                    startline = int(number.search(elem).group(0))
                elif "end:" in elem and number.search(elem) is not None:
                    endline = int(number.search(elem).group(0))
                if startline >= 0 and endline >= 0:
                    break
                j += 1
            if funcname.replace(" ", "") == method_name.replace(" ", ""):
                method_code = "\n".join(fmc.split("\n")[startline - 1 : endline])
                break
    os.system(f"rm {filepath.replace(' ','')}")
    return method_code


def parse_fixmorph(result_path, results_dir, output_path):
    fp = open(result_path)
    results = json.load(fp)
    fp.close()

    parsed_results = []
    err = []

    for result in tqdm(results):
        parsed_filename = result["file"]
        cve = result["cve-id"]
        id = result["id"]
        parsed_method = {}
        for method in result["method"]:
            filename = method.split("#")[1]
            assert parsed_filename == filename
            method_name = method.split("#")[-1]
            parsed_method[method] = {}
            if not os.path.exists(f"{results_dir}/{cve}#{id}/pa.c"):
                parsed_method[method] = {
                    "pa": "N/A",
                    "pb": "N/A",
                    "pc": "N/A",
                    "pc-patch": "N/A",
                    "pe": "N/A",
                }
                continue
            pa_code = get_method_code(f"{results_dir}/{cve}#{id}/pa.c", method_name)
            pb_code = get_method_code(f"{results_dir}/{cve}#{id}/pb.c", method_name)
            pc_code = get_method_code(f"{results_dir}/{cve}#{id}/pc.c", method_name)
            pc_patch_code = get_method_code(
                f"{results_dir}/{cve}#{id}/pc-patch.c", method_name
            )
            pe_code = get_method_code(f"{results_dir}/{cve}#{id}/pe.c", method_name)

            if pa_code == "" and pb_code == "":
                print(method)
                err.append(result)

            parsed_method[method]["pa"] = pa_code
            parsed_method[method]["pb"] = pb_code
            parsed_method[method]["pc"] = pc_code
            parsed_method[method]["pc-patch"] = pc_patch_code
            parsed_method[method]["pe"] = pe_code
        result["method"] = parsed_method

        parsed_results.append(result)

    print(len(err))
    fp = open(output_path, "w")
    json.dump(parsed_results, fp, indent=4)
    fp.close()


if __name__ == "__main__":
    pass
