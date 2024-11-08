import json
import os
import re
import subprocess
import sys
from datetime import datetime

from git import Repo
from pydriller import GitRepository
from pydriller.domain.commit import ModificationType
from pydriller.utils.conf import Conf
from tqdm import tqdm

sys.path.append("../")
import format_code
from config import CTAGS_PATH
from difftools import git_diff_code, parse_diff


def get_commit_time(repo_path: str, commit_id: str) -> datetime:
    repo = Repo(repo_path)
    return repo.commit(commit_id).committed_datetime


def get_patch_porting_pair(repo_path: str, commits: list[str]) -> tuple[str, str]:
    origin_commit = None
    target_commit = None
    origin_time = None
    target_time = None
    try:
        for i, commit in enumerate(commits):
            commit_time = get_commit_time(repo_path, commit)
            if i == 0:
                origin_commit = commit
                origin_time = commit_time
                target_commit = commit
                target_time = commit_time
                continue
            assert origin_time is not None
            assert target_time is not None
            if commit_time < origin_time:
                origin_commit = commit
                origin_time = commit_time
            if commit_time > target_time:
                target_commit = commit
                target_time = commit_time
    except Exception as e:
        print(e)
        assert len(commits) >= 2
        origin_commit = commits[0]
        target_commit = commits[-1]
    assert origin_commit is not None
    assert target_commit is not None
    return origin_commit, target_commit


def get_modified_map(modified_file_code: str, modified_lines: list, filename: str):
    fp = open(filename, "w")
    fp.write(modified_file_code)
    fp.close()
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
        number = re.compile(r"(\d+)")
        for result in alllist.split("\n"):
            if result == "" or result == " " or result == "\n":
                continue

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
                        pure_del = True
                        for l in range(startline, endline + 1):
                            if l in delete_lines:
                                delete_lines.remove(l)
                            else:
                                pure_del = False
                        if not pure_del:
                            modified_map[
                                str(startline) + "##" + str(endline) + "##" + funcname
                            ] = ""
                        break
                temp_delete_lines = delete_lines.copy()
                if delete_lines == []:
                    break
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
                        print(funcname)
                        pure_del = True
                        for l in range(startline, endline + 1):
                            if l in delete_lines:
                                delete_lines.remove(l)
                            else:
                                pure_del = False
                        if not pure_del:
                            modified_map[
                                str(startline) + "##" + str(endline) + "##" + funcname
                            ] = ""
                        break
                temp_delete_lines = delete_lines.copy()
                if delete_lines == []:
                    break
        os.remove(filename)
        return modified_map, alllist.split("\n")
    except subprocess.CalledProcessError as e:
        print(e)
        os.remove(filename)
        return {}, []
    except:
        print("func parsing error..")
        os.remove(filename)
        return {}, []


def get_old_new_map(info: dict):
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
    return new_old_map, old_new_map


def extract_commit_contents(repo_path: str, commit_id: str):
    conf = Conf(
        {
            "path_to_repo": str(repo_path),
            "skip_whitespaces": True,
            "include_remotes": True,
        }
    )
    repo = GitRepository(repo_path, conf=conf)
    method_info = []
    number = re.compile(r"(\d+)")
    try:
        if len(repo.get_commit(commit_id).parents) != 1:
            git_repo = Repo(repo_path)
            merge_commit = git_repo.commit(commit_id)
            diffs = merge_commit.diff(f"{commit_id}~1", create_patch=True)
            for diff_item in diffs:
                try:
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
                    old_content = diff_item.b_blob.data_stream.read().decode(
                        "utf-8", errors="ignore"
                    )
                    new_content = diff_item.a_blob.data_stream.read().decode(
                        "utf-8", errors="ignore"
                    )
                    pre_file_code = format_code.format_and_del_comment_c_cpp(
                        old_content
                    )
                    post_file_code = format_code.format_and_del_comment_c_cpp(
                        new_content
                    )
                    diff = git_diff_code(pre_file_code, post_file_code)
                    print(diff)
                    patch_info = parse_diff(diff)
                    methods_delete_add, pre_file_methods = get_modified_map(
                        pre_file_code, patch_info["delete"], filename.replace("/", "_")
                    )
                    if methods_delete_add == {} and pre_file_methods == []:
                        return []
                    methods_add_delete, post_file_methods = get_modified_map(
                        post_file_code, patch_info["add"], filename.replace("/", "_")
                    )
                    if methods_add_delete == {} and post_file_methods == []:
                        return []
                    new_old_map, old_new_map = get_old_new_map(patch_info)
                    for line_info in methods_delete_add.keys():
                        st = int(line_info.split("##")[0])
                        ed = int(line_info.split("##")[1])
                        not_change_line = -1
                        for line in range(st, ed + 1):
                            if line in old_new_map.keys():
                                not_change_line = line
                                break
                        if not_change_line == -1:
                            del methods_delete_add[line_info]
                            continue
                        for add_st_ed in methods_add_delete.keys():
                            st_add = int(add_st_ed.split("##")[0])
                            ed_add = int(add_st_ed.split("##")[1])
                            if (
                                old_new_map[not_change_line] >= st_add
                                and old_new_map[not_change_line] <= ed_add
                            ):
                                methods_delete_add[line_info] = add_st_ed
                                methods_add_delete[add_st_ed] = line_info
                                break

                        if methods_delete_add[line_info] == "":
                            for result in post_file_methods:
                                if result == "" or result == " " or result == "\n":
                                    continue

                                funcname = result.split("\t")[0]
                                if len(result.split("\t")) < 7:
                                    continue

                                if (
                                    result.split("\t")[3] == "f"
                                    and "function:" not in result.split("\t")[5]
                                    and "function:" not in result.split("\t")[6]
                                    and "end:" in result.split("\t")[-1]
                                ):
                                    startline = int(
                                        result.split("\t")[4].replace("line:", "")
                                    )
                                    endline = int(
                                        result.split("\t")[-1].replace("end:", "")
                                    )
                                    if (
                                        old_new_map[not_change_line] >= startline
                                        and old_new_map[not_change_line] <= endline
                                    ):
                                        methods_delete_add[line_info] = (
                                            f"{startline}##{endline}##{funcname}"
                                        )
                                        methods_add_delete[
                                            f"{startline}##{endline}##{funcname}"
                                        ] = line_info

                                elif "function" in result.split("\t"):
                                    elemList = result.split("\t")
                                    j = elemList.index("function")
                                    startline = -1
                                    endline = -1
                                    while j < len(elemList):
                                        elem = elemList[j]
                                        if "line:" in elem:
                                            startline = int(
                                                number.search(elem).group(0)
                                            )
                                        elif "end:" in elem:
                                            endline = int(number.search(elem).group(0))
                                        if startline >= 0 and endline >= 0:
                                            break
                                        j += 1
                                    if (
                                        old_new_map[not_change_line] >= startline
                                        and old_new_map[not_change_line] <= endline
                                    ):
                                        methods_delete_add[line_info] = (
                                            f"{startline}##{endline}##{funcname}"
                                        )
                                        methods_add_delete[
                                            f"{startline}##{endline}##{funcname}"
                                        ] = line_info

                    for line_info in methods_add_delete.keys():
                        if methods_add_delete[line_info] != "":
                            continue
                        st = int(line_info.split("##")[0])
                        ed = int(line_info.split("##")[1])
                        not_change_line = -1
                        for line in range(st, ed + 1):
                            if line in new_old_map.keys():
                                not_change_line = line
                                break
                        if not_change_line == -1:
                            continue
                        for result in pre_file_methods:
                            if result == "" or result == " " or result == "\n":
                                continue

                            funcname = result.split("\t")[0]
                            if len(result.split("\t")) < 7:
                                continue
                            if (
                                result.split("\t")[3] == "f"
                                and "function:" not in result.split("\t")[5]
                                and "function:" not in result.split("\t")[6]
                                and "end:" in result.split("\t")[-1]
                            ):
                                startline = int(
                                    result.split("\t")[4].replace("line:", "")
                                )
                                endline = int(
                                    result.split("\t")[-1].replace("end:", "")
                                )
                                if (
                                    new_old_map[not_change_line] >= startline
                                    and new_old_map[not_change_line] <= endline
                                ):
                                    methods_add_delete[line_info] = (
                                        f"{startline}##{endline}##{funcname}"
                                    )
                                    methods_delete_add[
                                        f"{startline}##{endline}##{funcname}"
                                    ] = line_info
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

                                if (
                                    new_old_map[not_change_line] >= startline
                                    and new_old_map[not_change_line] <= endline
                                ):
                                    methods_add_delete[line_info] = (
                                        f"{startline}##{endline}##{funcname}"
                                    )
                                    methods_delete_add[
                                        f"{startline}##{endline}##{funcname}"
                                    ] = line_info

                    before_method_code = ""
                    after_method_code = ""
                    for line_info in methods_delete_add.keys():
                        if methods_delete_add[line_info] == "":
                            continue
                        st = int(line_info.split("##")[0])
                        ed = int(line_info.split("##")[1])
                        method_name = line_info.split("##")[2]
                        before_file_code = pre_file_code.split("\n")
                        after_file_code = post_file_code.split("\n")
                        before_method_code = "\n".join(before_file_code[st - 1 : ed])
                        st_after = int(methods_delete_add[line_info].split("##")[0])
                        ed_after = int(methods_delete_add[line_info].split("##")[1])
                        after_method_code = "\n".join(
                            after_file_code[st_after - 1 : ed_after]
                        )
                        method = {
                            "filename": f"{filename}#{method_name}#{st}#{ed+1}",
                            "before_file_code": pre_file_code,
                            "before_func_code": before_method_code,
                            "after_file_code": post_file_code,
                            "after_func_code": after_method_code,
                        }
                        method_info.append(method)
                except Exception as e:
                    print(commit_id, "parse commit error!", e)
                    return []

        else:
            for file in repo.get_commit(commit_id).modifications:
                try:
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
                        file.source_code_before
                    )
                    post_file_code = format_code.format_and_del_comment_c_cpp(
                        file.source_code
                    )
                    diff = git_diff_code(pre_file_code, post_file_code)
                    patch_info = parse_diff(diff)
                    methods_delete_add, pre_file_methods = get_modified_map(
                        pre_file_code, patch_info["delete"], filename.replace("/", "_")
                    )
                    if methods_delete_add == {} and pre_file_methods == []:
                        return []
                    methods_add_delete, post_file_methods = get_modified_map(
                        post_file_code, patch_info["add"], filename.replace("/", "_")
                    )
                    if methods_add_delete == {} and post_file_methods == []:
                        return []

                    new_old_map, old_new_map = get_old_new_map(patch_info)
                    for line_info in methods_delete_add.keys():
                        st = int(line_info.split("##")[0])
                        ed = int(line_info.split("##")[1])
                        not_change_line = -1
                        for line in range(st, ed + 1):
                            if line in old_new_map.keys():
                                not_change_line = line
                                break

                        if not_change_line == -1:
                            del methods_delete_add[line_info]
                            continue
                        for add_st_ed in methods_add_delete.keys():
                            st_add = int(add_st_ed.split("##")[0])
                            ed_add = int(add_st_ed.split("##")[1])
                            if (
                                old_new_map[not_change_line] >= st_add
                                and old_new_map[not_change_line] <= ed_add
                            ):
                                methods_delete_add[line_info] = add_st_ed
                                methods_add_delete[add_st_ed] = line_info
                                break

                        if methods_delete_add[line_info] == "":
                            for result in post_file_methods:
                                if result == "" or result == " " or result == "\n":
                                    continue

                                funcname = result.split("\t")[0]
                                if len(result.split("\t")) < 7:
                                    continue

                                if (
                                    result.split("\t")[3] == "f"
                                    and "function:" not in result.split("\t")[5]
                                    and "function:" not in result.split("\t")[6]
                                    and "end:" in result.split("\t")[-1]
                                ):
                                    startline = int(
                                        result.split("\t")[4].replace("line:", "")
                                    )
                                    endline = int(
                                        result.split("\t")[-1].replace("end:", "")
                                    )
                                    if (
                                        old_new_map[not_change_line] >= startline
                                        and old_new_map[not_change_line] <= endline
                                    ):
                                        methods_delete_add[line_info] = (
                                            f"{startline}##{endline}##{funcname}"
                                        )
                                        methods_add_delete[
                                            f"{startline}##{endline}##{funcname}"
                                        ] = line_info

                                elif "function" in result.split("\t"):
                                    elemList = result.split("\t")
                                    j = elemList.index("function")
                                    startline = -1
                                    endline = -1
                                    while j < len(elemList):
                                        elem = elemList[j]
                                        if "line:" in elem:
                                            startline = int(
                                                number.search(elem).group(0)
                                            )
                                        elif "end:" in elem:
                                            endline = int(number.search(elem).group(0))
                                        if startline >= 0 and endline >= 0:
                                            break
                                        j += 1
                                    if (
                                        old_new_map[not_change_line] >= startline
                                        and old_new_map[not_change_line] <= endline
                                    ):
                                        methods_delete_add[line_info] = (
                                            f"{startline}##{endline}##{funcname}"
                                        )
                                        methods_add_delete[
                                            f"{startline}##{endline}##{funcname}"
                                        ] = line_info

                    for line_info in methods_add_delete.keys():
                        if methods_add_delete[line_info] != "":
                            continue
                        st = int(line_info.split("##")[0])
                        ed = int(line_info.split("##")[1])
                        not_change_line = -1
                        for line in range(st, ed + 1):
                            if line in new_old_map.keys():
                                not_change_line = line
                                break
                        if not_change_line == -1:
                            continue
                        for result in pre_file_methods:
                            if result == "" or result == " " or result == "\n":
                                continue

                            funcname = result.split("\t")[0]
                            if len(result.split("\t")) < 7:
                                continue
                            if (
                                result.split("\t")[3] == "f"
                                and "function:" not in result.split("\t")[5]
                                and "function:" not in result.split("\t")[6]
                                and "end:" in result.split("\t")[-1]
                            ):
                                startline = int(
                                    result.split("\t")[4].replace("line:", "")
                                )
                                endline = int(
                                    result.split("\t")[-1].replace("end:", "")
                                )
                                if (
                                    new_old_map[not_change_line] >= startline
                                    and new_old_map[not_change_line] <= endline
                                ):
                                    methods_add_delete[line_info] = (
                                        f"{startline}##{endline}##{funcname}"
                                    )
                                    methods_delete_add[
                                        f"{startline}##{endline}##{funcname}"
                                    ] = line_info
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

                                if (
                                    new_old_map[not_change_line] >= startline
                                    and new_old_map[not_change_line] <= endline
                                ):
                                    methods_add_delete[line_info] = (
                                        f"{startline}##{endline}##{funcname}"
                                    )
                                    methods_delete_add[
                                        f"{startline}##{endline}##{funcname}"
                                    ] = line_info
                    before_method_code = ""
                    after_method_code = ""
                    for line_info in methods_delete_add.keys():
                        if methods_delete_add[line_info] == "":
                            continue
                        st = int(line_info.split("##")[0])
                        ed = int(line_info.split("##")[1])
                        method_name = line_info.split("##")[2]
                        before_file_code = pre_file_code.split("\n")
                        after_file_code = post_file_code.split("\n")
                        before_method_code = "\n".join(before_file_code[st - 1 : ed])
                        st_after = int(methods_delete_add[line_info].split("##")[0])
                        ed_after = int(methods_delete_add[line_info].split("##")[1])
                        after_method_code = "\n".join(
                            after_file_code[st_after - 1 : ed_after]
                        )
                        method = {
                            "filename": f"{filename}#{method_name}#{st}#{ed+1}",
                            "before_file_code": pre_file_code,
                            "before_func_code": before_method_code,
                            "after_file_code": post_file_code,
                            "after_func_code": after_method_code,
                        }
                        method_info.append(method)
                except Exception as e:
                    print(commit_id, "parse commit error!", e)
                    return []
    except Exception as e:
        method_info = []
        return method_info
    return method_info


def extractor(cveid: str, origin_commit: str, repo_path: str) -> dict[str, dict]:
    owner_repo = repo_path.split("/")[-1]
    if "@@" in owner_repo:
        owner = owner_repo.split("@@")[0]
        repo = owner_repo.split("@@")[1]
    else:
        owner = ""
        repo = owner_repo

    origin_method_info = extract_commit_contents(repo_path, origin_commit)
    ground_truth = {}
    method_cnt = 0
    not_map_method_cnt = 0
    if len(origin_method_info) == 0:
        print(cveid, "parse error...")
        return {}
    else:
        ground_truth[cveid] = {
            "commit": origin_commit,
            "owner": owner,
            "repo": repo,
            "patch": {},
        }
        all_found = True
        for method in origin_method_info:
            method_name = method["filename"].split("#")[1]
            file_name = method["filename"].split("#")[0].split("/")[-1]

            not_found = True
            for origin_method in origin_method_info:
                origin_method_name = origin_method["filename"].split("#")[1]
                origin_file_name = (
                    origin_method["filename"].split("#")[0].split("/")[-1]
                )
                if method_name == origin_method_name and file_name == origin_file_name:
                    ground_truth[cveid]["patch"][method["filename"]] = {
                        "target_location": method["filename"],
                        "before_file_code": origin_method["before_file_code"],
                        "before_func_code": origin_method["before_func_code"],
                        "after_file_code": origin_method["after_file_code"],
                        "after_func_code": origin_method["after_func_code"],
                    }
                    not_found = False
                    break
            if not_found:
                print("WARNING:", cveid, method["filename"])
                all_found = False
                not_map_method_cnt += 1
                break
    if all_found:
        method_cnt += len(origin_method_info)
        return ground_truth
    else:
        return {}


def build_dataset(raw_data_path: str, output_path: str):
    with open(raw_data_path) as f:
        raw_data: dict[str, dict[str, str]] = json.load(f)

    results = {}
    errors = set()
    for cveid, info in tqdm(raw_data.items()):
        print(cveid)
        owner = info["repo"].split("/")[-2]
        repo = info["repo"].split("/")[-1]
        repo_path = f"。/gitrepo/{owner}@@{repo}"
        commit = info["commitId"]

        assert repo_path is not None
        result = extractor(cveid, commit, repo_path)
        if result == {}:
            errors.add(cveid)
        results.update(result)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)


if __name__ == "__main__":
    build_dataset(
        "../../dataset/emperical_cve_list.json",
        "../cve_origin_code.json",
    )
