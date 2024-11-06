import json
import os
import re
import subprocess
import sys

import format_code
from config import CTAGS_PATH
from difftools import git_diff_code, parse_diff
from git import Repo
from pydriller import GitRepository
from pydriller.domain.commit import ModificationType
from pydriller.utils.conf import Conf
from tqdm import tqdm


def is_outside(modified_file_code: str, modified_lines: list, filename: str):
    fp = open(filename, "w")
    fp.write(modified_file_code)
    fp.close()

    inside_method = []
    methods_num = set()

    try:
        finding_cfiles = subprocess.check_output(
            CTAGS_PATH + ' -f - --kinds-C=* --fields=neKSt "' + filename + '"',
            stderr=subprocess.STDOUT,
            shell=True,
        ).decode(errors="ignore")
        alllist = str(finding_cfiles)
        delete_lines = modified_lines.copy()
        temp_delete_lines = modified_lines.copy()
        modified_map = {}
        for result in alllist.split("\n"):
            if result == "" or result == " " or result == "\n":
                continue
            number = re.compile(r"(\d+)")

            filepath = result.split("\t")[1]
            funcname = result.split("\t")[0]
            if len(result.split("\t")) < 7:
                continue

            if (
                result.split("\t")[3] == "f"
                and "function:" not in result.split("\t")[5]
                and "function:" not in result.split("\t")[6]
                and "end:" in result.split("\t")[-1]
            ):
                startline = int(result.split("\t")[4].replace("line:", ""))
                endline = int(result.split("\t")[-1].replace("end:", ""))
                for line in temp_delete_lines:
                    if line >= startline and line <= endline:
                        inside_method.append(line)
                        methods_num.add(funcname)
            elif "function" in result.split("\t"):
                elemList = result.split("\t")
                j = elemList.index("function")
                startline = -1
                endline = -1
                while j < len(elemList):
                    elem = elemList[j]
                    if "line:" in elem:
                        startline = int(number.search(elem).group(0))
                    elif "end:" in elem:
                        endline = int(number.search(elem).group(0))
                    if startline >= 0 and endline >= 0:
                        break
                    j += 1
                for line in temp_delete_lines:
                    if line >= startline and line <= endline:
                        inside_method.append(line)
                        methods_num.add(funcname)

        os.remove(filename)
        result = [item for item in modified_lines if item not in inside_method]
        return result != [], methods_num
    except subprocess.CalledProcessError as e:
        print(e)
        os.remove(filename)
        return -1, set()
    except:
        print("func parsing error..")
        os.remove(filename)
        return -1, set()


def statistics(repo_path: str, commit_id: str):
    conf = Conf(
        {
            "path_to_repo": str(repo_path),
            "skip_whitespaces": True,
            "include_remotes": True,
        }
    )
    repo = GitRepository(repo_path, conf=conf)
    outside = False
    method_num = 0
    line_num = 0
    del_methods_nums = set()
    add_method_nums = set()
    for file in repo.get_commit(commit_id).modifications:
        try:
            if len(repo.get_commit(commit_id).parents) != 1:
                git_repo = Repo(repo_path)
                merge_commit = git_repo.commit(commit_id)
                for parent in repo.get_commit(commit_id).parents:
                    diffs = merge_commit.diff(parent, create_patch=True)
                    for diff_item in diffs:
                        if diff_item.a_path.split(".")[-1] not in [
                            "c",
                            "h",
                            "cpp",
                            "cxx",
                            "c++",
                            "cc",
                            "hpp",
                            "hxx",
                            "C",
                        ]:
                            continue
                        if "test/" in diff_item.a_path and "tests/" in diff_item.a_path:
                            continue
                        filename = diff_item.a_path
                        assert filename is not None
                        assert diff_item.a_blob is not None
                        assert diff_item.b_blob is not None
                        old_content = diff_item.a_blob.data_stream.read().decode(
                            "utf-8", errors="ignore"
                        )
                        new_content = diff_item.b_blob.data_stream.read().decode(
                            "utf-8", errors="ignore"
                        )
                        pre_file_code = format_code.format_and_del_comment_c_cpp(
                            old_content
                        )
                        post_file_code = format_code.format_and_del_comment_c_cpp(
                            new_content
                        )
                        diff = git_diff_code(pre_file_code, post_file_code)
                        patch_info = parse_diff(diff)
                        del_outside, del_methods_nums = is_outside(
                            pre_file_code,
                            patch_info["delete"],
                            filename.replace("/", "_"),
                        )
                        if del_outside == -1:
                            return -1, 0, 0
                        add_outside, add_method_nums = is_outside(
                            post_file_code,
                            patch_info["add"],
                            filename.replace("/", "_"),
                        )
                        if add_outside == -1:
                            return -1, 0, 0
                        if (
                            len(patch_info["add"]) != 0
                            and len(patch_info["delete"]) != 0
                        ):
                            method_num += len(
                                del_methods_nums.intersection(add_method_nums)
                            )
                        elif len(patch_info["add"]) != 0:
                            method_num += len(add_method_nums)
                        else:
                            method_num += len(del_methods_nums)
                        line_num += len(patch_info["delete"]) + len(patch_info["add"])
                        outside = outside or add_outside or del_outside
            else:
                if file.change_type != ModificationType.MODIFY:
                    continue
                if file.filename.split(".")[-1] not in [
                    "c",
                    "h",
                    "cpp",
                    "cxx",
                    "c++",
                    "cc",
                    "hpp",
                    "hxx",
                    "C",
                ]:
                    continue
                if "test/" in file.old_path and "tests/" in file.old_path:
                    continue

                filename = file.old_path
                assert filename is not None
                pre_file_code = format_code.format_and_del_comment_c_cpp(
                    file.source_code_before, del_macro=False, del_comments=True
                )
                post_file_code = format_code.format_and_del_comment_c_cpp(
                    file.source_code, del_macro=False, del_comments=True
                )
                diff = git_diff_code(pre_file_code, post_file_code)
                patch_info = parse_diff(diff)

                del_outside, del_methods_nums = is_outside(
                    pre_file_code, patch_info["delete"], filename.replace("/", "_")
                )
                if del_outside == -1:
                    return -1, 0, 0
                add_outside, add_method_nums = is_outside(
                    post_file_code, patch_info["add"], filename.replace("/", "_")
                )
                if add_outside == -1:
                    return -1, 0, 0
                if len(patch_info["add"]) != 0 and len(patch_info["delete"]) != 0:
                    method_num += len(del_methods_nums.intersection(add_method_nums))
                elif len(patch_info["add"]) != 0:
                    method_num += len(add_method_nums)
                else:
                    method_num += len(del_methods_nums)
                line_num += len(patch_info["delete"]) + len(patch_info["add"])
                outside = outside or add_outside or del_outside
        except Exception as e:
            print(commit_id, "parse commit error!", e)
            return -1, 0, 0

    return outside, method_num, line_num


def get_patch_info(cve: str, repo_path: str, commit_sha: str):
    patch_info = {}

    try:
        outside, method_num, line_num = statistics(repo_path, commit_sha)
    except Exception as e:
        print(e)
        return patch_info

    if outside == -1:
        return patch_info
    else:
        patch_info[cve] = {}
        patch_info[cve]["out"] = outside
        patch_info[cve]["method_num"] = method_num
        patch_info[cve]["line_num"] = line_num
        return patch_info


def get_macros_struct(modified_file_code: str, modified_lines: list, filename: str):
    fp = open(filename, "w")
    fp.write(modified_file_code)
    fp.close()

    vulTypes = {}
    vulTypes["struct"] = []
    vulTypes["macro"] = []
    vulTypes["function"] = []
    vulTypes["enum"] = []
    vulTypes["class"] = []
    vulTypes["variable"] = []
    vulTypes["function_def"] = []

    try:
        functionList = subprocess.check_output(
            CTAGS_PATH + ' -f - --kinds-C=* --fields=neKSt "' + filename + '"',
            stderr=subprocess.STDOUT,
            shell=True,
        ).decode(errors="replace")
        delete_lines = modified_lines.copy()
        temp_delete_lines = modified_lines.copy()
        modified_map = {}
        allFuncs = str(functionList).split("\n")
        func = "function"
        struct = "struct"
        macro = "macro"
        variable = "variable"
        localVar = "local"
        parameter = "parameter"
        member = "member"
        number = re.compile(r"(\d+)")

        for i in allFuncs:
            elemList = re.sub(r"[\t\s ]{2,}", "", i)
            elemList = elemList.split("\t")
            if i != "" and struct in elemList:
                j = elemList.index(struct)
                strStartLine = -1
                strEndLine = -1
                while j < len(elemList):
                    elem = elemList[j]
                    if "line:" in elem:
                        strStartLine = int(number.search(elem).group(0))
                    elif "end:" in elem:
                        strEndLine = int(number.search(elem).group(0))
                    if strStartLine >= 0 and strEndLine >= 0:
                        break
                    j += 1
                try:
                    vulTypes["struct"].append((strStartLine, strEndLine))
                except KeyError:
                    vulTypes["struct"] = [(strStartLine, strEndLine)]
            elif i != "" and func in elemList:
                j = elemList.index(func)
                strStartLine = -1
                strEndLine = -1
                while j < len(elemList):
                    elem = elemList[j]
                    match = number.search(elem)
                    if "line:" in elem and match:
                        strStartLine = int(number.search(elem).group(0))
                    elif "end:" in elem and match:
                        strEndLine = int(number.search(elem).group(0))
                    if strStartLine >= 0 and strEndLine >= 0:
                        break
                    j += 1
                try:
                    vulTypes["function"].append((strStartLine, strEndLine))
                except KeyError:
                    vulTypes["function"] = [(strStartLine, strEndLine)]
            elif i != "" and macro in elemList:
                j = elemList.index(macro)
                strStartLine = -1
                strEndLine = -1
                while j < len(elemList):
                    elem = elemList[j]
                    if "line:" in elem:
                        strStartLine = int(number.search(elem).group(0))
                    elif "end:" in elem:
                        strEndLine = int(number.search(elem).group(0))
                    if strStartLine >= 0 and strEndLine >= 0:
                        break
                    j += 1
                try:
                    vulTypes["macro"].append((strStartLine, strEndLine))
                except KeyError:
                    vulTypes["macro"] = [(strStartLine, strEndLine)]
            elif i != "" and "enum" in elemList:
                j = elemList.index("enum")
                strStartLine = -1
                strEndLine = -1
                while j < len(elemList):
                    elem = elemList[j]
                    if "line:" in elem:
                        strStartLine = int(number.search(elem).group(0))
                    elif "end:" in elem:
                        strEndLine = int(number.search(elem).group(0))
                    if strStartLine >= 0 and strEndLine >= 0:
                        break
                    j += 1
                try:
                    vulTypes["enum"].append((strStartLine, strEndLine))
                except KeyError:
                    vulTypes["enum"] = [(strStartLine, strEndLine)]
            elif i != "" and "class" in elemList:
                j = elemList.index("class")
                strStartLine = -1
                strEndLine = -1
                while j < len(elemList):
                    elem = elemList[j]
                    if "line:" in elem:
                        strStartLine = int(number.search(elem).group(0))
                    elif "end:" in elem:
                        strEndLine = int(number.search(elem).group(0))
                    if strStartLine >= 0 and strEndLine >= 0:
                        break
                    j += 1
                try:
                    vulTypes["class"].append((strStartLine, strEndLine))
                except KeyError:
                    vulTypes["class"] = [(strStartLine, strEndLine)]
            elif i != "" and "variable" in elemList:
                j = elemList.index("variable")
                strStartLine = -1
                strEndLine = -1
                while j < len(elemList):
                    elem = elemList[j]
                    if "line:" in elem:
                        strStartLine = int(number.search(elem).group(0))
                    elif "end:" in elem:
                        strEndLine = int(number.search(elem).group(0))
                    if strStartLine >= 0 and strEndLine >= 0:
                        break
                    j += 1
                try:
                    vulTypes["variable"].append((strStartLine, strEndLine))
                except KeyError:
                    vulTypes["variable"] = [(strStartLine, strEndLine)]
            elif i != "" and "member" in elemList:
                j = elemList.index("member")
                strStartLine = -1
                strEndLine = -1
                while j < len(elemList):
                    elem = elemList[j]
                    if "line:" in elem:
                        strStartLine = int(number.search(elem).group(0))
                    elif "end:" in elem:
                        strEndLine = int(number.search(elem).group(0))
                    if strStartLine >= 0 and strEndLine >= 0:
                        break
                    j += 1
                try:
                    vulTypes["variable"].append((strStartLine, strEndLine))
                except KeyError:
                    vulTypes["variable"] = [(strStartLine, strEndLine)]
            elif i != "" and "prototype" in elemList:
                j = elemList.index("prototype")
                strStartLine = -1
                strEndLine = -1
                while j < len(elemList):
                    elem = elemList[j]
                    if "line:" in elem:
                        strStartLine = int(number.search(elem).group(0))
                    elif "end:" in elem:
                        strEndLine = int(number.search(elem).group(0))
                    if strStartLine >= 0 and strEndLine >= 0:
                        break
                    j += 1
                try:
                    vulTypes["function_def"].append((strStartLine, strEndLine))
                except KeyError:
                    vulTypes["function_def"] = [(strStartLine, strEndLine)]
        os.remove(filename)
        return vulTypes
    except subprocess.CalledProcessError as e:
        print(e)
        os.remove(filename)
        return vulTypes
    except:
        print("func parsing error..")
        os.remove(filename)
        return vulTypes


def extract():
    fp = open("../dataset/emperical_cve_list.json")
    dataset = json.load(fp)
    fp.close()
    fp = open("patch_info.json")
    patch_info = json.load(fp)
    fp.close()
    errors = set()

    for cve in tqdm(dataset):
        info = get_patch_info(
            cve,
            os.path.join(
                "./gitrepo/",
                dataset[cve]["repo"]
                .replace("https://github.com/", "")
                .replace("/", "@@"),
            ),
            dataset[cve]["commitId"],
        )
        if info == {}:
            errors.add(cve)
        else:
            for cve in info:
                patch_info[cve] = info[cve]

    fp = open("errors.json", "w")
    json.dump(list(errors), fp, indent=4)
    fp.close()

    fp = open("patch_info.json", "w")
    json.dump(patch_info, fp, indent=4)
    fp.close()


def parse_out_methods():
    fp = open("./patch_info.json")
    patches = json.load(fp)
    fp.close()

    fp = open("../dataset/emperical_cve_list.json")
    dataset = json.load(fp)
    fp.close()

    errors = set()
    structs = set()
    macros = set()
    includes = set()
    others = set()
    enums = set()
    classes = set()
    variables = set()
    function_defs = set()

    for cve in tqdm(dataset):
        try:
            if not patches[cve]["out"]:
                continue
            repo_path = os.path.join(
                "./gitrepo/",
                dataset[cve]["repo"]
                .replace("https://github.com/", "")
                .replace("/", "@@"),
            )
            commit_id = dataset[cve]["commitId"]
            conf = Conf(
                {
                    "path_to_repo": str(repo_path),
                    "skip_whitespaces": True,
                    "include_remotes": True,
                }
            )
            repo = GitRepository(repo_path, conf=conf)
            struct = False
            macro = False
            include = False
            enum = False
            class_flag = False
            variable = False
            not_out_all = True
            function_def = True
            for file in repo.get_commit(commit_id).modifications:
                insides_del = []
                insides_add = []
                not_out_del = False
                not_out_add = False
                if file.change_type != ModificationType.MODIFY:
                    continue
                if file.filename.split(".")[-1] not in [
                    "c",
                    "h",
                    "cpp",
                    "cxx",
                    "c++",
                    "cc",
                    "hpp",
                    "hxx",
                    "C",
                ]:
                    continue
                if "test/" in file.old_path and "tests/" in file.old_path:
                    continue

                filename = file.old_path
                assert filename is not None
                pre_file_code = format_code.format_and_del_comment_c_cpp(
                    file.source_code_before, del_macro=False, del_comments=True
                )
                post_file_code = format_code.format_and_del_comment_c_cpp(
                    file.source_code, del_macro=False, del_comments=True
                )
                diff = git_diff_code(pre_file_code, post_file_code)
                patch_info = parse_diff(diff)
                vulTypes = get_macros_struct(
                    pre_file_code, patch_info["delete"], filename.replace("/", "_")
                )
                if vulTypes == {}:
                    errors.add(cve)
                    continue

                for line in patch_info["delete"]:
                    for st, ed in vulTypes["struct"]:
                        if line >= st and line <= ed:
                            struct = True
                            structs.add(cve)
                            break
                    for st, ed in vulTypes["macro"]:
                        if line >= st and line <= ed:
                            macro = True
                            macros.add(cve)
                            break
                    for st, ed in vulTypes["enum"]:
                        if line >= st and line <= ed:
                            enum = True
                            enums.add(cve)
                            break
                    for st, ed in vulTypes["class"]:
                        if line >= st and line <= ed:
                            class_flag = True
                            classes.add(cve)
                            break
                    for st, ed in vulTypes["variable"]:
                        if line >= st and line <= ed:
                            variable = True
                            variables.add(cve)
                            break
                    for st, ed in vulTypes["function_def"]:
                        if line >= st and line <= ed:
                            function_def = True
                            function_defs.add(cve)
                            break
                    for st, ed in vulTypes["function"]:
                        if line >= st and line <= ed:
                            insides_del.append(line)

                    if (
                        pre_file_code.split("\n")[line - 1]
                        .strip()
                        .replace(" ", "")
                        .startswith("#include")
                    ):
                        include = True
                        includes.add(cve)

                if insides_del == patch_info["delete"]:
                    not_out_del = True

                vulTypes = get_macros_struct(
                    post_file_code, patch_info["add"], filename.replace("/", "_")
                )
                if vulTypes == {}:
                    errors.add(cve)
                    continue

                for line in patch_info["add"]:
                    for st, ed in vulTypes["struct"]:
                        if line >= st and line <= ed:
                            struct = True
                            structs.add(cve)
                            break
                    for st, ed in vulTypes["macro"]:
                        if line >= st and line <= ed:
                            macro = True
                            macros.add(cve)
                            break
                    for st, ed in vulTypes["enum"]:
                        if line >= st and line <= ed:
                            enum = True
                            enums.add(cve)
                            break
                    for st, ed in vulTypes["class"]:
                        if line >= st and line <= ed:
                            class_flag = True
                            classes.add(cve)
                            break
                    for st, ed in vulTypes["variable"]:
                        if line >= st and line <= ed:
                            variable = True
                            variables.add(cve)
                            break
                    for st, ed in vulTypes["function_def"]:
                        if line >= st and line <= ed:
                            function_def = True
                            function_defs.add(cve)
                            break
                    for st, ed in vulTypes["function"]:
                        if line >= st and line <= ed:
                            insides_add.append(line)

                    if (
                        post_file_code.split("\n")[line - 1]
                        .strip()
                        .replace(" ", "")
                        .startswith("#include")
                    ):
                        include = True
                        includes.add(cve)

                if (
                    include
                    and macro
                    and struct
                    and enum
                    and class_flag
                    and variable
                    and function_def
                ):
                    break

                if insides_add == patch_info["add"]:
                    not_out_add = True

                not_out_all = not_out_all and not_out_add and not_out_del
            if (
                not include
                and not macro
                and not struct
                and not enum
                and not class_flag
                and not variable
                and not function_def
            ):
                others.add(cve)

            if not_out_all:
                print(cve)

        except Exception as e:
            print(commit_id, "parse commit error!", e)
            errors.add(cve)

    fp = open("patch_out_info.json", "w")
    out_info = {
        "struct": list(structs),
        "macro": list(macros),
        "include": list(includes),
        "enums": list(enums),
        "class": list(classes),
        "variable": list(variables),
        "function_def": list(function_defs),
        "others": list(others),
    }
    json.dump(out_info, fp, indent=4)
    fp.close()

    fp = open("errors.json", "w")
    json.dump(list(errors), fp, indent=4)
    fp.close()

    print(len(macros), len(structs), len(includes), len(others))


if __name__ == "__main__":
    extract()
