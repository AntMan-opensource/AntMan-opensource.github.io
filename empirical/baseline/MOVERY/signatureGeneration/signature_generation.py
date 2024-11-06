from email import errors
import git
from httpx import post
from tqdm import tqdm
from pydriller import GitRepository
from pydriller.domain.commit import ModificationType
from pydriller.utils.conf import Conf
import json
import re
from common import Language
import format
from difftools import git_diff_code, parse_diff
from config import CTAGS_PATH
import subprocess
import os
import ast_parser
import joern
import hashlib
from codefile import CodeFile, create_code_tree
import networkx as nx
from tqdm import tqdm

def normalize(string):
    return ''.join(string.replace('\r', '').replace('\t', '').split(' ')).lower()

def normalize_hash(string):
    return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(' ')).lower()

def abstract(body, ext):
    global delimiter

    tempFile = './dataset/temp/temp.' + ext
    ftemp = open(tempFile, 'w', encoding="UTF-8")
    ftemp.write(body)
    ftemp.close()

    abstractBody = ""
    originalFunctionBody = body
    abstractBody = originalFunctionBody

    command = CTAGS_PATH + ' -f - --kinds-C=* --fields=neKSt "' + tempFile + '"'
    try:
        astString = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True).decode(errors='ignore')
    except subprocess.CalledProcessError as e:
        print ("Parser Error:", e)
        astString = ""

    variables = []
    parameters = []
    dataTypes = []

    functionList = astString.split('\n')
    local = re.compile(r'local')
    parameter = re.compile(r'parameter')
    func = re.compile(r'(function)')
    parameterSpace = re.compile(r'\(\s*([^)]+?)\s*\)')
    word = re.compile(r'\w+')
    dataType = re.compile(r"(typeref:)\w*(:)")
    number = re.compile(r'(\d+)')
    funcBody = re.compile(r'{([\S\s]*)}')

    lines = []

    parameterList = []
    dataTypeList = []
    variableList = []

    for i in functionList:
        elemList = re.sub(r'[\t\s ]{2,}', '', i)
        elemList = elemList.split("\t")
        if i != '' and len(elemList) >= 6 and (local.fullmatch(elemList[3]) or local.fullmatch(elemList[4])):
            variables.append(elemList)
        
        if i != '' and len(elemList) >= 6 and (parameter.match(elemList[3]) or parameter.fullmatch(elemList[4])):
            parameters.append(elemList)

    for i in functionList:
        elemList = re.sub(r'[\t\s ]{2,}', '', i)
        elemList = elemList.split("\t")
        if i != '' and len(elemList) >= 8 and func.fullmatch(elemList[3]):
            lines = (int(number.search(elemList[4]).group(0)), int(number.search(elemList[7]).group(0)))

            lineNumber = 0
            for param in parameters:
                if number.search(param[4]):
                    lineNumber = int(number.search(param[4]).group(0))
                elif number.search(param[5]):
                    lineNumber = int(number.search(param[5]).group(0))
                if len(param) >= 4 and lines[0] <= int(lineNumber) <= lines[1]:
                    parameterList.append(param[0])
                    if len(param) >= 6 and dataType.search(param[5]):
                        dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", param[5])))
                    elif len(param) >= 7 and dataType.search(param[6]):
                        dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", param[6])))

            for variable in variables:
                if number.search(variable[4]):
                    lineNumber = int(number.search(variable[4]).group(0))
                elif number.search(variable[5]):
                    lineNumber = int(number.search(variable[5]).group(0))
                if len(variable) >= 4 and lines[0] <= int(lineNumber) <= lines[1]:
                    variableList.append(variable[0])
                    if len(variable) >= 6 and dataType.search(variable[5]):
                        dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", variable[5])))
                    elif len(variable) >= 7 and dataType.search(variable[6]):
                        dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", variable[6])))                        

    
    for param in parameterList:
        if len(param) == 0:
            continue
        try:
            paramPattern = re.compile("(^|\W)" + param + "(\W)")
            abstractBody = paramPattern.sub("\g<1>FPARAM\g<2>", abstractBody)
        except:
            pass

    for dtype in dataTypeList:
        if len(dtype) == 0:
            continue
        try:
            dtypePattern = re.compile("(^|\W)" + dtype + "(\W)")
            abstractBody = dtypePattern.sub("\g<1>DTYPE\g<2>", abstractBody)
        except:
            pass
    for lvar in variableList:
        if len(lvar) == 0:
            continue
        try:
            lvarPattern = re.compile("(^|\W)" + lvar + "(\W)")
            abstractBody = lvarPattern.sub("\g<1>LVAR\g<2>", abstractBody)
        except:
            pass
        

    os.remove(tempFile)
    print(parameterList)
    return abstractBody


def removeComment(string):
    c_regex = re.compile(
        r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE)
    return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])

def get_files_content_from_tag(repo_path, tag_name):
    repo = git.Repo(repo_path)
    
    tag_commit = repo.tags[tag_name].commit
    
    tree = tag_commit.tree
    
    files_content = {}
    
    for item in tree.traverse():
        if item.type == 'blob':  
            file_path = item.path
            file_content = item.data_stream.read().decode('utf-8', errors='ignore')  
            files_content[file_path] = file_content
    
    return files_content

def compare_versions(version1, version2):
    def tokenize(version):
        tokens = re.findall(r'\d+|[a-zA-Z]+', version)
        return [int(token) if token.isdigit() else token for token in tokens]
    
    v1_tokens = tokenize(version1)
    v2_tokens = tokenize(version2)
    
    for v1, v2 in zip(v1_tokens, v2_tokens):
        if isinstance(v1, int) and isinstance(v2, int):
            if v1 > v2:
                return 1
            elif v1 < v2:
                return -1
        else:
            if str(v1) > str(v2):
                return 1
            elif str(v1) < str(v2):
                return -1

    if len(v1_tokens) > len(v2_tokens):
        return 1
    elif len(v1_tokens) < len(v2_tokens):
        return -1
    
    return 0

def get_modified_map(modified_file_code: str, modified_lines: list, filename: str):
    fp = open(filename, "w")
    fp.write(modified_file_code)
    fp.close()
    try:
        finding_cfiles = subprocess.check_output(
            CTAGS_PATH + ' --fields=+ne -o - --sort=no ' + filename, stderr=subprocess.STDOUT, shell=True).decode(errors='ignore')
        alllist = str(finding_cfiles)
        delete_lines = modified_lines.copy()
        temp_delete_lines = modified_lines.copy()
        modified_map = {}
        for result in alllist.split('\n'):
            if result == '' or result == ' ' or result == '\n':
                continue

            filepath = result.split('\t')[1]
            funcname = result.split('\t')[0]
            if len(result.split('\t')) < 7:
                continue

            if result.split('\t')[3] == 'f' and 'function:' not in result.split('\t')[5] and 'function:' not in result.split('\t')[6] and 'end:' in result.split("\t")[-1]:
                startline = int(result.split('\t')[4].replace('line:', ''))
                endline = int(result.split('\t')[-1].replace('end:', ''))
                for line in temp_delete_lines:
                    if line >= startline and line <= endline:
                        pure_del = True
                        for l in range(startline, endline + 1):
                            if l in modified_lines:
                                delete_lines.remove(l)
                            else:
                                pure_del = False
                        if not pure_del:
                            modified_map[str(startline) + "##" + str(endline) + "##" + funcname] = ""
                        break
                temp_delete_lines = delete_lines.copy()
                if delete_lines == []:
                    break
        os.remove(filename)
        return modified_map, alllist.split('\n')
    except subprocess.CalledProcessError as e:
        print(e)
        os.remove(filename)
        return {}, []
    except:
        print('func parsing error..')
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
    conf = Conf({"path_to_repo": str(repo_path),
                 'skip_whitespaces': True,
                 'include_remotes': True})
    repo = GitRepository(repo_path, conf=conf)
    method_info = []
    print(commit_id, repo_path)
    for file in repo.get_commit(commit_id).modifications:
        try:
            if file.change_type != ModificationType.MODIFY:
                continue
            if file.filename.split(".")[-1] not in ["c", "h", "cpp", "cxx", "c++", "cc", "hpp", "hxx", "C"]:
                continue
            if "test/" in file.filename and "tests/" in file.filename:
                continue

            filename = file.old_path
            assert filename is not None
            pre_file_code = removeComment(file.source_code_before)
            post_file_code = removeComment(file.source_code)
            diff = git_diff_code(pre_file_code, post_file_code)
            patch_info = parse_diff(diff)
            methods_delete_add, pre_file_methods = get_modified_map(
                pre_file_code, patch_info["delete"], filename.replace("/", "_"))
            if methods_delete_add == {} and pre_file_methods == []:
                return []
            methods_add_delete, post_file_methods = get_modified_map(
                post_file_code, patch_info["add"], filename.replace("/", "_"))
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
                    if old_new_map[not_change_line] >= st_add and old_new_map[not_change_line] <= ed_add:
                        methods_delete_add[line_info] = add_st_ed
                        methods_add_delete[add_st_ed] = line_info
                        break

                if methods_delete_add[line_info] == "":
                    for result in post_file_methods:
                        if result == '' or result == ' ' or result == '\n':
                            continue

                        funcname = result.split('\t')[0]
                        if len(result.split('\t')) < 7:
                            continue

                        if result.split('\t')[3] == 'f' and 'function:' not in result.split('\t')[5] and 'function:' not in result.split('\t')[6] and 'end:' in result.split("\t")[-1]:
                            startline = int(result.split('\t')[4].replace('line:', ''))
                            endline = int(result.split('\t')[-1].replace('end:', ''))
                            if old_new_map[not_change_line] >= startline and old_new_map[not_change_line] <= endline:
                                methods_delete_add[line_info] = f"{startline}##{endline}##{funcname}"
                                methods_add_delete[f"{startline}##{endline}##{funcname}"] = line_info

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
                    if result == '' or result == ' ' or result == '\n':
                        continue

                    funcname = result.split('\t')[0]
                    if len(result.split('\t')) < 7:
                        continue
                    if result.split('\t')[3] == 'f' and 'function:' not in result.split('\t')[5] and 'function:' not in result.split('\t')[6] and 'end:' in result.split("\t")[-1]:
                        startline = int(result.split('\t')[4].replace('line:', ''))
                        endline = int(result.split('\t')[-1].replace('end:', ''))
                        if new_old_map[not_change_line] >= startline and new_old_map[not_change_line] <= endline:
                            methods_add_delete[line_info] = f"{startline}##{endline}##{funcname}"
                            methods_delete_add[f"{startline}##{endline}##{funcname}"] = line_info

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
                del_code = {}
                add_code = {}
                for line in patch_info['delete']:
                    if line >= st and line <= ed:
                        del_code[line-st+1] = before_file_code[line-1]
                before_method_code = "\n".join(before_file_code[st - 1:ed])
                st_after = int(methods_delete_add[line_info].split("##")[0])
                ed_after = int(methods_delete_add[line_info].split("##")[1])
                for line in patch_info['add']:
                    if line >= st_after and line <= ed_after:
                        add_code[line-st_after+1] = after_file_code[line-1]
                after_method_code = "\n".join(after_file_code[st_after - 1:ed_after])
                method = {
                    "filename": f"{filename}#{method_name}#{st}#{ed+1}",
                    "before_file_code": pre_file_code,
                    "before_func_code": before_method_code,
                    "after_file_code": post_file_code,
                    "after_func_code": after_method_code,
                    "del_code":del_code,
                    "add_code":add_code
                }
                method_info.append(method)
        except Exception as e:
            print(commit_id, 'parse commit error!', e)
            return []
    return method_info

def get_version_info(cve, repo_path):    
    fp = open("./git2cpe.json")
    git2cpe = json.load(fp)
    fp.close()

    fp = open("./matched_cpe_info.json")
    matched_cpe_info = json.load(fp)
    fp.close()

    if repo_path.split("/")[-1] not in git2cpe:
        return None, None
    

    
    cpe_name = git2cpe[repo_path.split("/")[-1]]
    if f'{repo_path.split("/")[-1]}@#@{cpe_name}' not in matched_cpe_info:
        return None, None

    fp = open(f"./cpe_cve/{cve}.json")
    contents = json.load(fp)
    fp.close()

    fd = "0.0.0.0"
    fo = "9.9.9.9.9.9.9"
    all_affected = False
    found_cpe = False

    for i in range(len(contents["matchStrings"])):
        
        if "matches" not in contents["matchStrings"][i]["matchString"].keys():
            cpe_info = contents["matchStrings"][i]["matchString"]
            
            cpe = ":".join(cpe_info["criteria"].split(":")[3:5])
            if cpe != cpe_name:
                continue
            else:
                found_cpe = True
            version = cpe_info["criteria"].split(":")[5]
            if version == "-":
                continue
            elif version == "*":
                all_affected = True
                break
            if compare_versions(version, fd) == 1:
                fd = version
            if compare_versions(version, fo) == -1:
                fo = version
            
            
            
        else:
            cpe_infos = contents["matchStrings"][i]["matchString"]["matches"]
            for cpe_info in cpe_infos:             
                cpe = ":".join(cpe_info["cpeName"].split(":")[3:5])
                if cpe != cpe_name:
                    continue
                else:
                    found_cpe = True
                
                version = cpe_info["cpeName"].split(":")[5]
                if version == "-":
                    continue
                elif version == "*":
                    all_affected = True
                    break
                
                if compare_versions(version, fd) == 1:
                    fd = version
                if compare_versions(version, fo) == -1:
                    fo = version
                    
    
    fgitd = ""
    fgito = ""
    if not found_cpe:
        return None, None
    if not all_affected:
        for v_cpe in matched_cpe_info[f'{repo_path.split("/")[-1]}@#@{cpe_name}']:
            
            if fd == v_cpe.split("@#@")[1]:
                fgitd = v_cpe.split("@#@")[0]
            if fo == v_cpe.split("@#@")[1]:
                fgito = v_cpe.split("@#@")[0]
    
    else:
        for v_cpe in matched_cpe_info[f'{repo_path.split("/")[-1]}@#@{cpe_name}']:
            version = v_cpe.split("@#@")[1]
            
            if version == "-":
                continue
            if compare_versions(version, fd) == 1:
                fd = version
                fgitd = v_cpe.split("@#@")[0]

            if compare_versions(version, fo) == -1:
                fo = version
                fgito = v_cpe.split("@#@")[0]
    
    if fgito == "":
        return None, None
    return fgitd, fgito

def extract_file_contents(code, filename, method_name):
    fp = open(filename, "w")
    fp.write(code)
    fp.close()
    try:
        finding_cfiles = subprocess.check_output(
            CTAGS_PATH + ' --fields=+ne -o - --sort=no ' + filename, stderr=subprocess.STDOUT, shell=True).decode(errors='ignore')
        alllist = str(finding_cfiles)
        for result in alllist.split('\n'):
            if result == '' or result == ' ' or result == '\n':
                continue

            filepath = result.split('\t')[1]
            funcname = result.split('\t')[0]
            if len(result.split('\t')) < 7:
                continue

            if result.split('\t')[3] == 'f' and 'function:' not in result.split('\t')[5] and 'function:' not in result.split('\t')[6] and 'end:' in result.split("\t")[-1]:
                startline = int(result.split('\t')[4].replace('line:', ''))
                endline = int(result.split('\t')[-1].replace('end:', ''))
                if funcname == method_name:
                    os.remove(filename)
                    return startline, endline
        os.remove(filename)
        return -1, -1
    except subprocess.CalledProcessError as e:
        print(e)
        os.remove(filename)
        return -1, -1
    except:
        print('func parsing error..')
        os.remove(filename)
        return -1, -1

def get_direct_pdg_by_line(line, pdg_dir, method_name, codes,abs_codes, suffix):        
    pre_cdg = []
    pre_cfg = []
    pre_ddg = []
    post_cdg = []
    post_ddg = []
    post_cfg = []
    for pdg_file in os.listdir(pdg_dir):
        try:
            pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(os.path.join(pdg_dir, pdg_file))
        except Exception as e:
            print(f"Error in reading {pdg_file}")
            os.remove(os.path.join(pdg_dir, pdg_file))
            continue
        
        get_method = False
        for node in pdg.nodes:
            if pdg.nodes[node]['NODE_TYPE']=='METHOD':
                if pdg.nodes[node]['NAME'] == method_name:
                    get_method = True
        
        if not get_method:
            continue
        
        node_id = -1
        for node in pdg.nodes:
            line_number = pdg.nodes[node]['LINE_NUMBER']
            
            if int(line_number) == line:
                node_id = node


        if node_id == -1:
            if line != 1:
                pre_cfg.append({
                                "line":line-2,
                                f"orig_{suffix}":codes[line-2],
                                f"abs_{suffix}":abs_codes[line-2],
                                f"orig_norm_{suffix}":normalize(codes[line-2]),
                                f"abs_norm_{suffix}":normalize(abs_codes[line-2])
                            })
            if line != len(codes):
                post_cfg.append({
                                "line":line-2,
                                f"orig_{suffix}":codes[line-2],
                                f"abs_{suffix}":abs_codes[line-2],
                                f"orig_norm_{suffix}":normalize(codes[line-2]),
                                f"abs_norm_{suffix}":normalize(abs_codes[line-2])
                            })
            

        for u, v, d in pdg.edges(data=True):
            if u == node_id:
                if "DDG" in d['label']:
                    post_ddg.append({
                                "line":int(pdg.nodes[v]['LINE_NUMBER']),
                                f"orig_{suffix}":codes[int(pdg.nodes[v]['LINE_NUMBER'])-1],
                                f"abs_{suffix}":abs_codes[int(pdg.nodes[v]['LINE_NUMBER'])-1],
                                f"orig_norm_{suffix}":normalize(codes[int(pdg.nodes[v]['LINE_NUMBER'])-1]),
                                f"abs_norm_{suffix}":normalize(abs_codes[int(pdg.nodes[v]['LINE_NUMBER'])-1])
                            })
                elif "CDG" in d['label']:
                    post_cdg.append({
                                "line":int(pdg.nodes[v]['LINE_NUMBER']),
                                f"orig_{suffix}":codes[int(pdg.nodes[v]['LINE_NUMBER'])-1],
                                f"abs_{suffix}":abs_codes[int(pdg.nodes[v]['LINE_NUMBER'])-1],
                                f"orig_norm_{suffix}":normalize(codes[int(pdg.nodes[v]['LINE_NUMBER'])-1]),
                                f"abs_norm_{suffix}":normalize(abs_codes[int(pdg.nodes[v]['LINE_NUMBER'])-1])
                            })
                elif "CFG" in d['label']:
                    post_cfg.append({
                                "line":int(pdg.nodes[v]['LINE_NUMBER']),
                                f"orig_{suffix}":codes[int(pdg.nodes[v]['LINE_NUMBER'])-1],
                                f"abs_{suffix}":abs_codes[int(pdg.nodes[v]['LINE_NUMBER'])-1],
                                f"orig_norm_{suffix}":normalize(codes[int(pdg.nodes[v]['LINE_NUMBER'])-1]),
                                f"abs_norm_{suffix}":normalize(abs_codes[int(pdg.nodes[v]['LINE_NUMBER'])-1])
                            })
            
            elif v == node_id:
                if "DDG" in d['label']:
                    pre_ddg.append({
                                "line":int(pdg.nodes[u]['LINE_NUMBER']),
                                f"orig_{suffix}":codes[int(pdg.nodes[u]['LINE_NUMBER'])-1],
                                f"abs_{suffix}":abs_codes[int(pdg.nodes[u]['LINE_NUMBER'])-1],
                                f"orig_norm_{suffix}":normalize(codes[int(pdg.nodes[u]['LINE_NUMBER'])-1]),
                                f"abs_norm_{suffix}":normalize(abs_codes[int(pdg.nodes[u]['LINE_NUMBER'])-1])
                            })
                elif "CDG" in d['label']:
                    pre_cdg.append({
                                "line":int(pdg.nodes[u]['LINE_NUMBER']),
                                f"orig_{suffix}":codes[int(pdg.nodes[u]['LINE_NUMBER'])-1],
                                f"abs_{suffix}":abs_codes[int(pdg.nodes[u]['LINE_NUMBER'])-1],
                                f"orig_norm_{suffix}":normalize(codes[int(pdg.nodes[u]['LINE_NUMBER'])-1]),
                                f"abs_norm_{suffix}":normalize(abs_codes[int(pdg.nodes[u]['LINE_NUMBER'])-1])
                            })
                elif "CFG" in d['label']:
                    pre_cfg.append({
                                "line":int(pdg.nodes[u]['LINE_NUMBER']),
                                f"orig_{suffix}":codes[int(pdg.nodes[u]['LINE_NUMBER'])-1],
                                f"abs_{suffix}":abs_codes[int(pdg.nodes[u]['LINE_NUMBER'])-1],
                                f"orig_norm_{suffix}":normalize(codes[int(pdg.nodes[u]['LINE_NUMBER'])-1]),
                                f"abs_norm_{suffix}":normalize(abs_codes[int(pdg.nodes[u]['LINE_NUMBER'])-1])
                            })
    
    return pre_cdg, pre_cfg, pre_ddg, post_cdg, post_ddg, post_cfg


def signature_generation(cve, commit, repo_path, overwrite=False):
    global idx
    fd, fo = get_version_info(cve, repo_path)
    fo_content = None
    if fo is not None:
        fo_content = get_files_content_from_tag(repo_path, fo)
    
    method_info = extract_commit_contents(repo_path, commit)
    errors = []
    for method in method_info:
        try:
            filename = method["filename"].split("#")[0]
            method_name = method["filename"].split("#")[1]
            fp = open("dataset/oss_idx.txt", "a")
            fp.write(f"{repo_path.split('/')[-1].replace('@@','##')}@@{idx}\n")
            fp.close()
            
            fp = open("dataset/idx2cve.txt", "a")
            fp.write(f"{idx}##{cve}\n")
            fp.close()
            
            vulBody = {"vul_body":[]}
            common_line = []
            plus_line = []
            for code in method["before_func_code"].split("\n"):
                vulBody['vul_body'].append(normalize(code))
            abs_code = normalize(abstract(method["before_func_code"], "c"))
            add_abs_code = normalize(abstract(method["after_func_code"], "c"))
            file_name = os.path.basename(filename)
            file_path_md5 = hashlib.md5(method["filename"].encode()).hexdigest()[:4]
            cache_dir = f"cache/{cve}/{file_name}#{method_name}#{file_path_md5}"
            os.makedirs(cache_dir, exist_ok=True)

            pre_codefile = CodeFile(filename, method["before_func_code"])
            post_codefile = CodeFile(filename, method["after_func_code"])    
            pre_dir = os.path.join(cache_dir, "pre")
            post_dir = os.path.join(cache_dir, "post")

            create_code_tree([pre_codefile], pre_dir, overwrite=overwrite)
            create_code_tree([post_codefile], post_dir, overwrite=overwrite)
            joern.export_with_preprocess_and_merge(os.path.join(pre_dir, "code"), pre_dir, Language.C)
            joern.export_with_preprocess_and_merge(os.path.join(post_dir, "code"), post_dir, Language.C)
            dependent_pat = {
                "pre_cfg":[],
                "post_cfg":[],
                "pre_ddg":[],
                "post_ddg":[],
                "pre_cdg":[],
                "post_cdg":[]
            }

            if fo_content is not None and filename in fo_content:
                
                vulBody['old_body'] = []
                st, ed = extract_file_contents(removeComment(fo_content[filename]), filename.replace("/","_"), method_name)
                if st != -1 and ed != -1:
                    dependent = {
                        "vul":{
                            "pre_cfg":[],
                            "post_cfg":[],
                            "pre_ddg":[],
                            "post_ddg":[],
                            "pre_cdg":[],
                            "post_cdg":[]
                        },
                        "old":{
                            "pre_cfg":[],
                            "post_cfg":[],
                            "pre_ddg":[],
                            "post_ddg":[],
                            "pre_cdg":[],
                            "post_cdg":[]
                        }
                    }
                    for code in fo_content[filename].split("\n")[st-1: ed]:
                        vulBody['old_body'].append(normalize(code))
                    diff = git_diff_code(method["before_func_code"], "\n".join(removeComment(fo_content[filename]).split("\n")[st-1: ed]))
                    patch_info = parse_diff(diff)
                    _, old_new_map = get_old_new_map(patch_info)
                    
                    old_codefile = CodeFile(filename, "\n".join(removeComment(fo_content[filename]).split("\n")[st-1: ed]))
                    old_dir = os.path.join(cache_dir, "old")
                    create_code_tree([old_codefile], old_dir, overwrite=overwrite)
                    joern.export_with_preprocess_and_merge(os.path.join(old_dir, "code"), old_dir, Language.C)
                    for line in method['del_code']:
                        if line in patch_info['delete']:
                            continue
                        else:
                            common_line.append({
                                "old_line":old_new_map[line],
                                "vul_line":line,
                                "vul_body":method['del_code'][line],
                                "abs_body":abs_code.split("\n")[line-1]
                            })
                            dependent["vul"]["pre_cdg"], dependent["vul"]["pre_cfg"], dependent["vul"]["pre_ddg"], dependent["vul"]["post_cdg"], dependent["vul"]["post_ddg"], dependent["vul"]["post_cfg"] = get_direct_pdg_by_line(line, os.path.join(pre_dir, "pdg"), method_name, method["before_func_code"].split("\n"),abstract(method["before_func_code"], "c").split("\n"), "vul")
                            dependent["old"]["pre_cdg"], dependent["old"]["pre_cfg"], dependent["old"]["pre_ddg"], dependent["old"]["post_cdg"], dependent["old"]["post_ddg"], dependent["old"]["post_cfg"] = get_direct_pdg_by_line(old_new_map[line], os.path.join(old_dir, "pdg"), method_name, removeComment(fo_content[filename]).split("\n")[st-1: ed], abstract(fo_content[filename], "c").split("\n"), "vul")
                    if common_line != []:
                        fp = open(f"dataset/vulESSLines/{idx}_common.txt", "w")
                        json.dump(common_line, fp)
                        fp.close()
                    fp = open(f"dataset/vulDEPLines/{idx}_depen.txt", "w")
                    json.dump(dependent, fp)
                    fp.close()
                    diff = git_diff_code(method["after_func_code"], "\n".join(removeComment(fo_content[filename]).split("\n")[st-1: ed]))
                    patch_info = parse_diff(diff)
                    _, old_new_map = get_old_new_map(patch_info)
                    for line in method['add_code']:
                        if line not in patch_info["delete"]:
                            continue
                        plus_line.append({
                            "pat_line":line,
                            "pat_body":method['add_code'][line],
                            "abs_body":add_abs_code.split("\n")[line-1]
                        })
                        dependent_pat["pre_cdg"], dependent_pat["pre_cfg"], dependent_pat["pre_ddg"], dependent_pat["post_cdg"], dependent_pat["post_ddg"], dependent_pat["post_cfg"] = get_direct_pdg_by_line(line, os.path.join(post_dir, "pdg"), method_name, method["after_func_code"].split("\n"), abstract(method["after_func_code"], "c").split("\n"), "pat")
                        
                    fp = open(f"dataset/patESSLines/{idx}_plus.txt", "w")
                    json.dump(plus_line, fp)
                    fp.close()
            else:
                dependent = {
                    "pre_cfg":[],
                    "post_cfg":[],
                    "pre_ddg":[],
                    "post_ddg":[],
                    "pre_cdg":[],
                    "post_cdg":[]
                }
                for line in method['add_code']:
                    try:
                        
                        plus_line.append({
                                "pat_line":line,
                                "pat_body":method['add_code'][line],
                                "abs_body":add_abs_code.split("\n")[line-1]
                            })
                        dependent_pat["pre_cdg"], dependent_pat["pre_cfg"], dependent_pat["pre_ddg"], dependent_pat["post_cdg"], dependent_pat["post_ddg"], dependent_pat["post_cfg"] = get_direct_pdg_by_line(line, os.path.join(post_dir, "pdg"), method_name, method["after_func_code"].split("\n"), abstract(method["after_func_code"], "c").split("\n"), "pat")
                    except:
                        fp = open("errors.txt","w")
                        fp.write(cve)
                        fp.write(" " + method["filename"] + "\n")
                        fp.close()


                fp = open(f"dataset/patESSLines/{idx}_plus.txt", "w")
                json.dump(plus_line, fp)
                fp.close()

                for line in method['del_code']:
                    common_line.append({
                                "vul_line":line,
                                "vul_body":method['del_code'][line],
                                "abs_body":abs_code.split("\n")[line-1]
                    })
                    dependent["pre_cdg"], dependent["pre_cfg"], dependent["pre_ddg"], dependent["post_cdg"], dependent["post_ddg"], dependent["post_cfg"] = get_direct_pdg_by_line(line, os.path.join(pre_dir, "pdg"), method_name, method["before_func_code"].split("\n"),normalize(abstract(method["before_func_code"], "c")).split("\n"), "vul")
                
                if common_line != []:
                    fp = open(f"dataset/noOldESSLines/{idx}_common.txt", "w")
                    json.dump(common_line, fp)
                    fp.close()
                fp = open(f"dataset/noOldDEPLines/{idx}_depen.txt", "w")
                json.dump(dependent, fp)
                fp.close()



            fp = open(f"dataset/patDEPLines/{idx}_depen.txt", "w")
            json.dump(dependent_pat, fp)
            fp.close()
                    

            fp = open(f"dataset/vulBodySet/{idx}_vulFuncs.txt", "w")
            json.dump(vulBody, fp)
            fp.close()
            idx += 1
        except Exception as e:
            print("ERROR when generate " + cve + " " + method["filename"] + " " + str(e))
            errors.append((cve,  method["filename"]))
            fp = open("error.json","w")
            json.dump(errors, fp, indent=4)
            fp.close()           



if __name__ == "__main__":
    global idx
    idx = 1
    fp = open("./cve_list.json")
    dataset = json.load(fp)
    fp.close()

    fp = open("dataset/idx2cve.txt")
    lines = fp.readlines()
    fp.close()

    already_run = set()


    for line in lines:
        cve = line.split("##")[1].strip()
        already_run.add(cve)
        idx = max(idx, int(line.split("##")[0]))

    print(idx)


    for cve in tqdm(dataset):
        commitId = dataset[cve]["commitId"]
        repo_path = os.path.join("./signature_repo_cache/", "@@".join(dataset[cve]["repo"].split("/")[-2:]))
        signature_generation(cve, commitId, repo_path)

