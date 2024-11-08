import json


def get_generality_results():
    results = {}
    fp = open("generality_rvd_results.json")
    datas = json.load(fp)
    fp.close()

    gt = set()

    for tool in datas:
        print(tool)
        tp = 0
        fp_num = 0
        fn = 0
        results[tool] = {}
        for key in datas[tool]:
            if datas[tool][key] == "TP":
                tp += 1
                gt.add(key)
            elif datas[tool][key] == "FP":
                fp_num += 1
                gt.add(key)
            else:
                fn += 1
                gt.add(key)
        print(tp, fp_num, fn)
        results[tool]["TP"] = tp
        results[tool]["FP"] = fp_num
        results[tool]["FN"] = fn
        results[tool]["Pre."] = tp / (tp + fp_num)
        results[tool]["Rec."] = tp / (tp + fn)
        results[tool]["F1."] = (
            2
            * results[tool]["Pre."]
            * results[tool]["Rec."]
            / (results[tool]["Rec."] + results[tool]["Pre."])
        )

    fp = open("rvd_generality_results.json", "w")
    json.dump(results, fp, indent=4)
    fp.close()


if __name__ == "__main__":
    get_generality_results()
