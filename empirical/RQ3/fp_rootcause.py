import ast
import json
from collections import Counter

import icecream as ic
import pandas as pd

TOOLLIST = ["vuddy", "mvp", "v1scan", "fire", "movery"]
tool_reasons = {each: [] for each in TOOLLIST}


def fn_features_map():
    # 文件路径
    file_path = "datas/FP_samples_per_tool.xlsx"
    # 读取Excel文件，跳过表头
    df = pd.read_excel(file_path, header=0)
    results_reasons = {}
    for index, row in df.iterrows():
        # 处理每一行数据
        data2review = row.to_dict()
        key = f"{data2review['CVE']}##{data2review['target_repo']}##{data2review['target_tag']}"
        if key not in results_reasons:
            results_reasons[key] = []
        for reason in ast.literal_eval(data2review["FP reasons"]):
            # print(reason)
            results_reasons[key].append(reason)

    fp = open("datas/result_feature.json")
    results_features = json.load(fp)
    fp.close()

    fp_type_reasons = {}
    fp_type_reasons_all = {}
    fp_type_reasons["all"] = {}
    fp_type_reasons_all["all"] = []

    cnt = 0
    key_cnt = 0

    for key in results_features:
        ## 未采样直接跳过
        if key not in results_reasons:
            continue
        key_cnt += 1
        type = results_features[key].split("__split__")[0]
        method_num = results_features[key].split("__split__")[1]
        if type not in fp_type_reasons:
            fp_type_reasons[type] = {}
            fp_type_reasons_all[type] = []
        if method_num not in fp_type_reasons[type]:
            fp_type_reasons[type][method_num] = []
        if method_num not in fp_type_reasons["all"]:
            fp_type_reasons["all"][method_num] = []

        count = {}
        for reason in results_reasons[key]:
            for res in reason:
                if res not in count:
                    count[res] = 0
                else:
                    continue
                fp_type_reasons[type][method_num].append(res)
                fp_type_reasons_all[type].append(res)
                fp_type_reasons["all"][method_num].append(res)
                fp_type_reasons_all["all"].append(res)
                cnt += 1

    cnt = 0
    results = {}
    for type in fp_type_reasons:
        results[type] = {}
        reasons_count = Counter(fp_type_reasons_all[type])

        for reason in reasons_count:
            cnt += reasons_count[reason]

        top_n = 3
        top_items = reasons_count.most_common(top_n)

        total_count = sum(reasons_count.values())
        top_percentage = [
            (item, count, (count / total_count) * 100) for item, count in top_items
        ]

        sum_count = 0
        for item, count, percentage in top_percentage:
            results[type][item] = f"{count}({percentage/100:.2f})"
            print(f"Item: {item}, Count: {count}, Percentage: {percentage/100:.2f}")
            sum_count += percentage / 100
        results[type]["all"] = f"{sum_count:.2f}"
        for method_num in fp_type_reasons[type]:
            results[type][method_num] = {}
            reasons_count = Counter(fp_type_reasons[type][method_num])
            top_n = 5
            top_items = reasons_count.most_common(top_n)

            total_count = sum(reasons_count.values())
            top_percentage = [
                (item, count, (count / total_count) * 100) for item, count in top_items
            ]

            sum_count = 0
            for item, count, percentage in top_percentage:
                results[type][method_num][item] = f"{count}({percentage/100:.2f})"
                print(f"Item: {item}, Count: {count}, Percentage: {percentage/100:.2f}")
                sum_count += percentage / 100
            results[type][method_num]["all"] = f"{sum_count:.2f}"
    fp = open("datas/RQ3_results_FP.json", "w")
    json.dump(results, fp, indent=4)
    fp.close()


if __name__ == "__main__":
    # fp_iterator()
    fn_features_map()
