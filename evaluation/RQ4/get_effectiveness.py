import json


def get_antman():
    fp = open("raw_results.json")
    all_results = json.load(fp)
    fp.close()

    fp = open("ground truth.json")
    gt = json.load(fp)
    fp.close()

    fp = open("cve_lists.json")
    cve_list = json.load(fp)
    fp.close()
    results_antman = {}

    for repo in gt:
        for tag in gt[repo]:
            for cve in gt[repo][tag]:
                if cve not in cve_list:
                    continue
                repo_name = f"{repo}-{tag.replace('/', '_')}"
                key = f"{cve}##{repo}##{tag}"
                if (
                    all_results[repo_name][cve] == "vul"
                    and gt[repo][tag][cve]["results"] == "TP"
                ):
                    results_antman[key] = "TP"
                elif (
                    all_results[repo_name][cve] == "vul"
                    and gt[repo][tag][cve]["results"] == "FP"
                ):
                    results_antman[key] = "FP"
                elif (
                    all_results[repo_name][cve] == "not vul"
                    and gt[repo][tag][cve]["results"] == "TP"
                ):
                    results_antman[key] = "FN"

    fp = open("results_antman_effectiveness.json", "w")
    json.dump(results_antman, fp, indent=4)
    fp.close()


def get_results_effectiveness():
    fp = open("results_other_tools.json")
    other_tools = json.load(fp)
    fp.close()

    gt = set()
    tp = set()
    for tool in other_tools:
        for key in other_tools[tool]:
            if other_tools[tool][key] != "FP":
                tp.add(key)
            gt.add(key)

    fp = open("results_antman_effectiveness.json")
    results_antman = json.load(fp)
    fp.close()

    fp = open("results_features.json")
    result_feature = json.load(fp)
    fp.close()

    result_effectiveness = {}
    for cve_res in results_antman:
        if cve_res not in result_feature:
            continue
        if cve_res not in gt:
            continue
        try:
            result_effectiveness[result_feature[cve_res]][results_antman[cve_res]] += 1
        except:
            if result_feature[cve_res] not in result_effectiveness:
                result_effectiveness[result_feature[cve_res]] = {}
            result_effectiveness[result_feature[cve_res]][results_antman[cve_res]] = 1
    types = {
        "origin__split__type1__split__S",
        "origin__split__type2__split__S",
        "origin__split__type34__split__S",
        "target__split__type1__split__S",
        "target__split__type2__split__S",
        "target__split__type34__split__S",
        "origin__split__type1__split__M",
        "origin__split__type2__split__M",
        "origin__split__type34__split__M",
        "target__split__type1__split__M",
        "target__split__type2__split__M",
        "target__split__type34__split__M",
    }
    for type in types:
        if type not in result_effectiveness:
            result_effectiveness[type] = {}
            result_effectiveness[type]["prec."] = 0.00
            result_effectiveness[type]["rec."] = 0.00

        if "TP" not in result_effectiveness[type]:
            result_effectiveness[type]["prec."] = 0.00
            result_effectiveness[type]["rec."] = 0.00
            continue
        if "FP" not in result_effectiveness[type]:
            result_effectiveness[type]["prec."] = 1.00
            result_effectiveness[type]["FP"] = 0.00
        if "FN" not in result_effectiveness[type]:
            result_effectiveness[type]["rec."] = 1.00
            result_effectiveness[type]["FN"] = 0.00

        result_effectiveness[type]["prec."] = round(
            result_effectiveness[type]["TP"]
            / (result_effectiveness[type]["TP"] + result_effectiveness[type]["FP"]),
            2,
        )
        result_effectiveness[type]["rec."] = round(
            result_effectiveness[type]["TP"]
            / (result_effectiveness[type]["TP"] + result_effectiveness[type]["FN"]),
            2,
        )

    fp = open("results_RQ4.json", "w")
    json.dump(result_effectiveness, fp, indent=4)
    fp.close()


def refine_results():
    results = {}

    fp = open("results_RQ4.json")
    raw_results = json.load(fp)
    fp.close()

    for type in raw_results:
        if "TP" not in raw_results[type]:
            raw_results[type]["TP"] = 0

        if "FP" not in raw_results[type]:
            raw_results[type]["FP"] = 0

        if "FN" not in raw_results[type]:
            raw_results[type]["FN"] = 0

    results = {}
    results["type1__split__S"] = {}
    results["type1__split__S"]["TP"] = (
        raw_results["target__split__type1__split__S"]["TP"]
        + raw_results["origin__split__type1__split__S"]["TP"]
    )
    results["type1__split__S"]["FP"] = (
        raw_results["target__split__type1__split__S"]["FP"]
        + raw_results["origin__split__type1__split__S"]["FP"]
    )
    results["type1__split__S"]["FN"] = (
        raw_results["target__split__type1__split__S"]["FN"]
        + raw_results["origin__split__type1__split__S"]["FN"]
    )
    try:
        results["type1__split__S"]["prec."] = results["type1__split__S"]["TP"] / (
            results["type1__split__S"]["TP"] + results["type1__split__S"]["FP"]
        )
    except:
        results["type1__split__S"]["prec."] = 0.00
    try:
        results["type1__split__S"]["rec."] = results["type1__split__S"]["TP"] / (
            results["type1__split__S"]["TP"] + results["type1__split__S"]["FN"]
        )
    except:
        results["type1__split__S"]["rec."] = 0.00
    try:
        results["type1__split__S"]["f1."] = (
            2
            * results["type1__split__S"]["prec."]
            * results["type1__split__S"]["rec."]
            / (results["type1__split__S"]["prec."] + results["type1__split__S"]["rec."])
        )
    except:
        results["type1__split__S"]["f1."] = 0.00

    results["type2__split__S"] = {}
    results["type2__split__S"]["TP"] = (
        raw_results["target__split__type2__split__S"]["TP"]
        + raw_results["origin__split__type2__split__S"]["TP"]
    )
    results["type2__split__S"]["FP"] = (
        raw_results["target__split__type2__split__S"]["FP"]
        + raw_results["origin__split__type2__split__S"]["FP"]
    )
    results["type2__split__S"]["FN"] = (
        raw_results["target__split__type2__split__S"]["FN"]
        + raw_results["origin__split__type2__split__S"]["FN"]
    )
    try:
        results["type2__split__S"]["prec."] = results["type2__split__S"]["TP"] / (
            results["type2__split__S"]["TP"] + results["type2__split__S"]["FP"]
        )
    except:
        results["type2__split__S"]["prec."] = 0.00
    try:
        results["type2__split__S"]["rec."] = results["type2__split__S"]["TP"] / (
            results["type2__split__S"]["TP"] + results["type2__split__S"]["FN"]
        )
    except:
        results["type2__split__S"]["rec."] = 0.00
    try:
        results["type2__split__S"]["f1."] = (
            2
            * results["type2__split__S"]["prec."]
            * results["type2__split__S"]["rec."]
            / (results["type2__split__S"]["prec."] + results["type2__split__S"]["rec."])
        )
    except:
        results["type2__split__S"]["f1."] = 0.00

    results["type34__split__S"] = {}
    results["type34__split__S"]["TP"] = (
        raw_results["target__split__type34__split__S"]["TP"]
        + raw_results["origin__split__type34__split__S"]["TP"]
    )
    results["type34__split__S"]["FP"] = (
        raw_results["target__split__type34__split__S"]["FP"]
        + raw_results["origin__split__type34__split__S"]["FP"]
    )
    results["type34__split__S"]["FN"] = (
        raw_results["target__split__type34__split__S"]["FN"]
        + raw_results["origin__split__type34__split__S"]["FN"]
    )
    try:
        results["type34__split__S"]["prec."] = results["type34__split__S"]["TP"] / (
            results["type34__split__S"]["TP"] + results["type34__split__S"]["FP"]
        )
    except:
        results["type34__split__S"]["prec."] = 0.00
    try:
        results["type34__split__S"]["rec."] = results["type34__split__S"]["TP"] / (
            results["type34__split__S"]["TP"] + results["type34__split__S"]["FN"]
        )
    except:
        results["type34__split__S"]["rec."] = 0.00
    try:
        results["type34__split__S"]["f1."] = (
            2
            * results["type34__split__S"]["prec."]
            * results["type34__split__S"]["rec."]
            / (
                results["type34__split__S"]["prec."]
                + results["type34__split__S"]["rec."]
            )
        )
    except:
        results["type34__split__S"]["f1."] = 0.00

    results["type1__split__M"] = {}
    results["type1__split__M"]["TP"] = (
        raw_results["target__split__type1__split__M"]["TP"]
        + raw_results["origin__split__type1__split__M"]["TP"]
    )
    results["type1__split__M"]["FP"] = (
        raw_results["target__split__type1__split__M"]["FP"]
        + raw_results["origin__split__type1__split__M"]["FP"]
    )
    results["type1__split__M"]["FN"] = (
        raw_results["target__split__type1__split__M"]["FN"]
        + raw_results["origin__split__type1__split__M"]["FN"]
    )
    try:
        results["type1__split__M"]["prec."] = results["type1__split__M"]["TP"] / (
            results["type1__split__M"]["TP"] + results["type1__split__M"]["FP"]
        )
    except:
        results["type1__split__M"]["prec."] = 0.00
    try:
        results["type1__split__M"]["rec."] = results["type1__split__M"]["TP"] / (
            results["type1__split__M"]["TP"] + results["type1__split__M"]["FN"]
        )
    except:
        results["type1__split__M"]["rec."] = 0.00
    try:
        results["type1__split__M"]["f1."] = (
            2
            * results["type1__split__M"]["prec."]
            * results["type1__split__M"]["rec."]
            / (results["type1__split__M"]["prec."] + results["type1__split__M"]["rec."])
        )
    except:
        results["type1__split__M"]["f1."] = 0.00

    results["type2__split__M"] = {}
    results["type2__split__M"]["TP"] = (
        raw_results["target__split__type2__split__M"]["TP"]
        + raw_results["origin__split__type2__split__M"]["TP"]
    )
    results["type2__split__M"]["FP"] = (
        raw_results["target__split__type2__split__M"]["FP"]
        + raw_results["origin__split__type2__split__M"]["FP"]
    )
    results["type2__split__M"]["FN"] = (
        raw_results["target__split__type2__split__M"]["FN"]
        + raw_results["origin__split__type2__split__M"]["FN"]
    )
    try:
        results["type2__split__M"]["prec."] = results["type2__split__M"]["TP"] / (
            results["type2__split__M"]["TP"] + results["type2__split__M"]["FP"]
        )
    except:
        results["type2__split__M"]["prec."] = 0.00
    try:
        results["type2__split__M"]["rec."] = results["type2__split__M"]["TP"] / (
            results["type2__split__M"]["TP"] + results["type2__split__M"]["FN"]
        )
    except:
        results["type2__split__M"]["rec."] = 0.00
    try:
        results["type2__split__M"]["f1."] = (
            2
            * results["type2__split__M"]["prec."]
            * results["type2__split__M"]["rec."]
            / (results["type2__split__M"]["prec."] + results["type2__split__M"]["rec."])
        )
    except:
        results["type2__split__M"]["f1."] = 0.00

    results["type34__split__M"] = {}
    results["type34__split__M"]["TP"] = (
        raw_results["target__split__type34__split__M"]["TP"]
        + raw_results["origin__split__type34__split__M"]["TP"]
    )
    results["type34__split__M"]["FP"] = (
        raw_results["target__split__type34__split__M"]["FP"]
        + raw_results["origin__split__type34__split__M"]["FP"]
    )
    results["type34__split__M"]["FN"] = (
        raw_results["target__split__type34__split__M"]["FN"]
        + raw_results["origin__split__type34__split__M"]["FN"]
    )
    try:
        results["type34__split__M"]["prec."] = results["type34__split__M"]["TP"] / (
            results["type34__split__M"]["TP"] + results["type34__split__M"]["FP"]
        )
    except:
        results["type34__split__M"]["prec."] = 0.00
    try:
        results["type34__split__M"]["rec."] = results["type34__split__M"]["TP"] / (
            results["type34__split__M"]["TP"] + results["type34__split__M"]["FN"]
        )
    except:
        results["type34__split__M"]["rec."] = 0.00
    try:
        results["type34__split__M"]["f1."] = (
            2
            * results["type34__split__M"]["prec."]
            * results["type34__split__M"]["rec."]
            / (
                results["type34__split__M"]["prec."]
                + results["type34__split__M"]["rec."]
            )
        )
    except:
        results["type34__split__M"]["f1."] = 0.00

    results["type1__split__all"] = {}
    results["type1__split__all"]["TP"] = (
        results["type1__split__S"]["TP"] + results["type1__split__M"]["TP"]
    )
    results["type1__split__all"]["FP"] = (
        results["type1__split__S"]["FP"] + results["type1__split__M"]["FP"]
    )
    results["type1__split__all"]["FN"] = (
        results["type1__split__S"]["FN"] + results["type1__split__M"]["FN"]
    )
    try:
        results["type1__split__all"]["prec."] = results["type1__split__all"]["TP"] / (
            results["type1__split__all"]["TP"] + results["type1__split__all"]["FP"]
        )
    except:
        results["type1__split__all"]["prec."] = 0.00
    try:
        results["type1__split__all"]["rec."] = results["type1__split__all"]["TP"] / (
            results["type1__split__all"]["TP"] + results["type1__split__all"]["FN"]
        )
    except:
        results["type1__split__all"]["rec."] = 0.00
    try:
        results["type1__split__all"]["f1."] = (
            2
            * results["type1__split__all"]["prec."]
            * results["type1__split__all"]["rec."]
            / (
                results["type1__split__all"]["prec."]
                + results["type1__split__all"]["rec."]
            )
        )
    except:
        results["type1__split__all"]["f1."] = 0.00

    results["type2__split__all"] = {}
    results["type2__split__all"]["TP"] = (
        results["type2__split__S"]["TP"] + results["type2__split__M"]["TP"]
    )
    results["type2__split__all"]["FP"] = (
        results["type2__split__S"]["FP"] + results["type2__split__M"]["FP"]
    )
    results["type2__split__all"]["FN"] = (
        results["type2__split__S"]["FN"] + results["type2__split__M"]["FN"]
    )
    try:
        results["type2__split__all"]["prec."] = results["type2__split__all"]["TP"] / (
            results["type2__split__all"]["TP"] + results["type2__split__all"]["FP"]
        )
    except:
        results["type2__split__all"]["prec."] = 0.00
    try:
        results["type2__split__all"]["rec."] = results["type2__split__all"]["TP"] / (
            results["type2__split__all"]["TP"] + results["type2__split__all"]["FN"]
        )
    except:
        results["type2__split__all"]["rec."] = 0.00
    try:
        results["type2__split__all"]["f1."] = (
            2
            * results["type2__split__all"]["prec."]
            * results["type2__split__all"]["rec."]
            / (
                results["type2__split__all"]["prec."]
                + results["type2__split__all"]["rec."]
            )
        )
    except:
        results["type2__split__all"]["f1."] = 0.00

    results["type34__split__all"] = {}
    results["type34__split__all"]["TP"] = (
        results["type34__split__S"]["TP"] + results["type34__split__M"]["TP"]
    )
    results["type34__split__all"]["FP"] = (
        results["type34__split__S"]["FP"] + results["type34__split__M"]["FP"]
    )
    results["type34__split__all"]["FN"] = (
        results["type34__split__S"]["FN"] + results["type34__split__M"]["FN"]
    )
    try:
        results["type34__split__all"]["prec."] = results["type34__split__all"]["TP"] / (
            results["type34__split__all"]["TP"] + results["type34__split__all"]["FP"]
        )
    except:
        results["type34__split__all"]["prec."] = 0.00
    try:
        results["type34__split__all"]["rec."] = results["type34__split__all"]["TP"] / (
            results["type34__split__all"]["TP"] + results["type34__split__all"]["FN"]
        )
    except:
        results["type34__split__all"]["rec."] = 0.00
    try:
        results["type34__split__all"]["f1."] = (
            2
            * results["type34__split__all"]["prec."]
            * results["type34__split__all"]["rec."]
            / (
                results["type34__split__all"]["prec."]
                + results["type34__split__all"]["rec."]
            )
        )
    except:
        results["type34__split__all"]["f1."] = 0.00

    results["all__split__S"] = {}
    results["all__split__S"]["TP"] = (
        results["type2__split__S"]["TP"]
        + results["type34__split__S"]["TP"]
        + results["type1__split__S"]["TP"]
    )
    results["all__split__S"]["FP"] = (
        results["type2__split__S"]["FP"]
        + results["type34__split__S"]["FP"]
        + results["type1__split__S"]["FP"]
    )
    results["all__split__S"]["FN"] = (
        results["type2__split__S"]["FN"]
        + results["type34__split__S"]["FN"]
        + results["type1__split__S"]["FN"]
    )
    try:
        results["all__split__S"]["prec."] = results["all__split__S"]["TP"] / (
            results["all__split__S"]["TP"] + results["all__split__S"]["FP"]
        )
    except:
        results["all__split__S"]["prec."] = 0.00
    try:
        results["all__split__S"]["rec."] = results["all__split__S"]["TP"] / (
            results["all__split__S"]["TP"] + results["all__split__S"]["FN"]
        )
    except:
        results["all__split__S"]["rec."] = 0.00
    try:
        results["all__split__S"]["f1."] = (
            2
            * results["all__split__S"]["prec."]
            * results["all__split__S"]["rec."]
            / (results["all__split__S"]["prec."] + results["all__split__S"]["rec."])
        )
    except:
        results["all__split__S"]["f1."] = 0.00

    results["all__split__M"] = {}
    results["all__split__M"]["TP"] = (
        results["type2__split__M"]["TP"]
        + results["type34__split__M"]["TP"]
        + results["type1__split__M"]["TP"]
    )
    results["all__split__M"]["FP"] = (
        results["type2__split__M"]["FP"]
        + results["type34__split__M"]["FP"]
        + results["type1__split__M"]["FP"]
    )
    results["all__split__M"]["FN"] = (
        results["type2__split__M"]["FN"]
        + results["type34__split__M"]["FN"]
        + results["type1__split__M"]["FN"]
    )
    try:
        results["all__split__M"]["prec."] = results["all__split__M"]["TP"] / (
            results["all__split__M"]["TP"] + results["all__split__M"]["FP"]
        )
    except:
        results["all__split__M"]["prec."] = 0.00
    try:
        results["all__split__M"]["rec."] = results["all__split__M"]["TP"] / (
            results["all__split__M"]["TP"] + results["all__split__M"]["FN"]
        )
    except:
        results["all__split__M"]["rec."] = 0.00
    try:
        results["all__split__M"]["f1."] = (
            2
            * results["all__split__M"]["prec."]
            * results["all__split__M"]["rec."]
            / (results["all__split__M"]["prec."] + results["all__split__M"]["rec."])
        )
    except:
        results["all__split__M"]["f1."] = 0.00

    results["all__split__all"] = {}
    results["all__split__all"]["TP"] = (
        results["type2__split__all"]["TP"]
        + results["type34__split__all"]["TP"]
        + results["type1__split__all"]["TP"]
    )
    results["all__split__all"]["FP"] = (
        results["type2__split__all"]["FP"]
        + results["type34__split__all"]["FP"]
        + results["type1__split__all"]["FP"]
    )
    results["all__split__all"]["FN"] = (
        results["type2__split__all"]["FN"]
        + results["type34__split__all"]["FN"]
        + results["type1__split__all"]["FN"]
    )
    try:
        results["all__split__all"]["prec."] = results["all__split__all"]["TP"] / (
            results["all__split__all"]["TP"] + results["all__split__all"]["FP"]
        )
    except:
        results["all__split__all"]["prec."] = 0.00
    try:
        results["all__split__all"]["rec."] = results["all__split__all"]["TP"] / (
            results["all__split__all"]["TP"] + results["all__split__all"]["FN"]
        )
    except:
        results["all__split__all"]["rec."] = 0.00
    try:
        results["all__split__all"]["f1."] = (
            2
            * results["all__split__all"]["prec."]
            * results["all__split__all"]["rec."]
            / (results["all__split__all"]["prec."] + results["all__split__all"]["rec."])
        )
    except:
        results["all__split__all"]["f1."] = 0.00

    fp = open("results_RQ4.json", "w")
    json.dump(results, fp, indent=4)
    fp.close()


if __name__ == "__main__":
    get_antman()
    get_results_effectiveness()
    refine_results()
