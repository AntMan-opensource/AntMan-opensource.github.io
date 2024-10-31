import json


def get_results_RQ2():
    fp = open("datas/patch_info.json")
    patch_info = json.load(fp)
    fp.close()

    fp = open("datas/all_results.json")
    results = json.load(fp)
    fp.close()

    fp = open("datas/patch_result_info.json")
    patch_result_info = json.load(fp)
    fp.close()

    results_RQ2 = {}

    all_results_features = {}
    for key in patch_result_info:
        for origin_transfer_pair in patch_result_info[key]:
            cve = origin_transfer_pair.split("##")[0]
            type34 = False
            type2 = False
            for info in patch_result_info[key][origin_transfer_pair]:
                if patch_result_info[key][origin_transfer_pair][info] == "type34":
                    type34 = True
                elif patch_result_info[key][origin_transfer_pair][info] == "type2":
                    type2 = True

    fp = open("datas/result_feature.json")
    result_feature = json.load(fp)
    fp.close()

    for tool in results:
        if tool not in results_RQ2:
            results_RQ2[tool] = {}
        for cve_res in results[tool]:
            if cve_res not in result_feature:
                continue
            if results[tool][cve_res] != "FP":
                try:
                    all_results_features[result_feature[cve_res]].append(
                        cve_res.split("##")[0]
                    )
                except:
                    all_results_features[result_feature[cve_res]] = [
                        cve_res.split("##")[0]
                    ]
            try:
                results_RQ2[tool][result_feature[cve_res]][results[tool][cve_res]] += 1
            except:
                if result_feature[cve_res] not in results_RQ2[tool]:
                    results_RQ2[tool][result_feature[cve_res]] = {}
                results_RQ2[tool][result_feature[cve_res]][results[tool][cve_res]] = 1

    types = {
        "origin__split__type1__split__S",
        "origin__split__type2__split__S",
        "origin__split__type34__split__S",
        "transfer__split__type1__split__S",
        "transfer__split__type2__split__S",
        "transfer__split__type34__split__S",
        "origin__split__type1__split__M",
        "origin__split__type2__split__M",
        "origin__split__type34__split__M",
        "transfer__split__type1__split__M",
        "transfer__split__type2__split__M",
        "transfer__split__type34__split__M",
    }
    for tool in results_RQ2:
        for type in types:
            if type not in results_RQ2[tool]:
                results_RQ2[tool][type] = {}
                results_RQ2[tool][type]["prec."] = 0.00
                results_RQ2[tool][type]["rec."] = 0.00

            if "TP" not in results_RQ2[tool][type]:
                results_RQ2[tool][type]["prec."] = 0.00
                results_RQ2[tool][type]["rec."] = 0.00
                continue
            if "FP" not in results_RQ2[tool][type]:
                results_RQ2[tool][type]["prec."] = 1.00
                results_RQ2[tool][type]["FP"] = 0.00
            if "FN" not in results_RQ2[tool][type]:
                results_RQ2[tool][type]["rec."] = 1.00
                results_RQ2[tool][type]["FN"] = 0.00

            results_RQ2[tool][type]["prec."] = round(
                results_RQ2[tool][type]["TP"]
                / (results_RQ2[tool][type]["TP"] + results_RQ2[tool][type]["FP"]),
                2,
            )
            results_RQ2[tool][type]["rec."] = round(
                results_RQ2[tool][type]["TP"]
                / (results_RQ2[tool][type]["TP"] + results_RQ2[tool][type]["FN"]),
                2,
            )

    return results_RQ2


def refine_results_RQ2(raw_results):
    results = {}
    for tool in raw_results:
        for type in raw_results[tool]:
            if "TP" not in raw_results[tool][type]:
                raw_results[tool][type]["TP"] = 0

            if "FP" not in raw_results[tool][type]:
                raw_results[tool][type]["FP"] = 0

            if "FN" not in raw_results[tool][type]:
                raw_results[tool][type]["FN"] = 0

    for tool in raw_results:
        results[tool] = {}
        results[tool]["type1__split__S"] = {}
        results[tool]["type1__split__S"]["TP"] = (
            raw_results[tool]["transfer__split__type1__split__S"]["TP"]
            + raw_results[tool]["origin__split__type1__split__S"]["TP"]
        )
        results[tool]["type1__split__S"]["FP"] = (
            raw_results[tool]["transfer__split__type1__split__S"]["FP"]
            + raw_results[tool]["origin__split__type1__split__S"]["FP"]
        )
        results[tool]["type1__split__S"]["FN"] = (
            raw_results[tool]["transfer__split__type1__split__S"]["FN"]
            + raw_results[tool]["origin__split__type1__split__S"]["FN"]
        )
        try:
            results[tool]["type1__split__S"]["prec."] = results[tool][
                "type1__split__S"
            ]["TP"] / (
                results[tool]["type1__split__S"]["TP"]
                + results[tool]["type1__split__S"]["FP"]
            )
        except:
            results[tool]["type1__split__S"]["prec."] = 0.00
        try:
            results[tool]["type1__split__S"]["rec."] = results[tool]["type1__split__S"][
                "TP"
            ] / (
                results[tool]["type1__split__S"]["TP"]
                + results[tool]["type1__split__S"]["FN"]
            )
        except:
            results[tool]["type1__split__S"]["rec."] = 0.00
        try:
            results[tool]["type1__split__S"]["f1."] = (
                2
                * results[tool]["type1__split__S"]["prec."]
                * results[tool]["type1__split__S"]["rec."]
                / (
                    results[tool]["type1__split__S"]["prec."]
                    + results[tool]["type1__split__S"]["rec."]
                )
            )
        except:
            results[tool]["type1__split__S"]["f1."] = 0.00

        results[tool]["type2__split__S"] = {}
        results[tool]["type2__split__S"]["TP"] = (
            raw_results[tool]["transfer__split__type2__split__S"]["TP"]
            + raw_results[tool]["origin__split__type2__split__S"]["TP"]
        )
        results[tool]["type2__split__S"]["FP"] = (
            raw_results[tool]["transfer__split__type2__split__S"]["FP"]
            + raw_results[tool]["origin__split__type2__split__S"]["FP"]
        )
        results[tool]["type2__split__S"]["FN"] = (
            raw_results[tool]["transfer__split__type2__split__S"]["FN"]
            + raw_results[tool]["origin__split__type2__split__S"]["FN"]
        )
        try:
            results[tool]["type2__split__S"]["prec."] = results[tool][
                "type2__split__S"
            ]["TP"] / (
                results[tool]["type2__split__S"]["TP"]
                + results[tool]["type2__split__S"]["FP"]
            )
        except:
            results[tool]["type2__split__S"]["prec."] = 0.00
        try:
            results[tool]["type2__split__S"]["rec."] = results[tool]["type2__split__S"][
                "TP"
            ] / (
                results[tool]["type2__split__S"]["TP"]
                + results[tool]["type2__split__S"]["FN"]
            )
        except:
            results[tool]["type2__split__S"]["rec."] = 0.00
        try:
            results[tool]["type2__split__S"]["f1."] = (
                2
                * results[tool]["type2__split__S"]["prec."]
                * results[tool]["type2__split__S"]["rec."]
                / (
                    results[tool]["type2__split__S"]["prec."]
                    + results[tool]["type2__split__S"]["rec."]
                )
            )
        except:
            results[tool]["type2__split__S"]["f1."] = 0.00

        results[tool]["type34__split__S"] = {}
        results[tool]["type34__split__S"]["TP"] = (
            raw_results[tool]["transfer__split__type34__split__S"]["TP"]
            + raw_results[tool]["origin__split__type34__split__S"]["TP"]
        )
        results[tool]["type34__split__S"]["FP"] = (
            raw_results[tool]["transfer__split__type34__split__S"]["FP"]
            + raw_results[tool]["origin__split__type34__split__S"]["FP"]
        )
        results[tool]["type34__split__S"]["FN"] = (
            raw_results[tool]["transfer__split__type34__split__S"]["FN"]
            + raw_results[tool]["origin__split__type34__split__S"]["FN"]
        )
        try:
            results[tool]["type34__split__S"]["prec."] = results[tool][
                "type34__split__S"
            ]["TP"] / (
                results[tool]["type34__split__S"]["TP"]
                + results[tool]["type34__split__S"]["FP"]
            )
        except:
            results[tool]["type34__split__S"]["prec."] = 0.00
        try:
            results[tool]["type34__split__S"]["rec."] = results[tool][
                "type34__split__S"
            ]["TP"] / (
                results[tool]["type34__split__S"]["TP"]
                + results[tool]["type34__split__S"]["FN"]
            )
        except:
            results[tool]["type34__split__S"]["rec."] = 0.00
        try:
            results[tool]["type34__split__S"]["f1."] = (
                2
                * results[tool]["type34__split__S"]["prec."]
                * results[tool]["type34__split__S"]["rec."]
                / (
                    results[tool]["type34__split__S"]["prec."]
                    + results[tool]["type34__split__S"]["rec."]
                )
            )
        except:
            results[tool]["type34__split__S"]["f1."] = 0.00

        results[tool]["type1__split__M"] = {}
        results[tool]["type1__split__M"]["TP"] = (
            raw_results[tool]["transfer__split__type1__split__M"]["TP"]
            + raw_results[tool]["origin__split__type1__split__M"]["TP"]
        )
        results[tool]["type1__split__M"]["FP"] = (
            raw_results[tool]["transfer__split__type1__split__M"]["FP"]
            + raw_results[tool]["origin__split__type1__split__M"]["FP"]
        )
        results[tool]["type1__split__M"]["FN"] = (
            raw_results[tool]["transfer__split__type1__split__M"]["FN"]
            + raw_results[tool]["origin__split__type1__split__M"]["FN"]
        )
        try:
            results[tool]["type1__split__M"]["prec."] = results[tool][
                "type1__split__M"
            ]["TP"] / (
                results[tool]["type1__split__M"]["TP"]
                + results[tool]["type1__split__M"]["FP"]
            )
        except:
            results[tool]["type1__split__M"]["prec."] = 0.00
        try:
            results[tool]["type1__split__M"]["rec."] = results[tool]["type1__split__M"][
                "TP"
            ] / (
                results[tool]["type1__split__M"]["TP"]
                + results[tool]["type1__split__M"]["FN"]
            )
        except:
            results[tool]["type1__split__M"]["rec."] = 0.00
        try:
            results[tool]["type1__split__M"]["f1."] = (
                2
                * results[tool]["type1__split__M"]["prec."]
                * results[tool]["type1__split__M"]["rec."]
                / (
                    results[tool]["type1__split__M"]["prec."]
                    + results[tool]["type1__split__M"]["rec."]
                )
            )
        except:
            results[tool]["type1__split__M"]["f1."] = 0.00

        results[tool]["type2__split__M"] = {}
        results[tool]["type2__split__M"]["TP"] = (
            raw_results[tool]["transfer__split__type2__split__M"]["TP"]
            + raw_results[tool]["origin__split__type2__split__M"]["TP"]
        )
        results[tool]["type2__split__M"]["FP"] = (
            raw_results[tool]["transfer__split__type2__split__M"]["FP"]
            + raw_results[tool]["origin__split__type2__split__M"]["FP"]
        )
        results[tool]["type2__split__M"]["FN"] = (
            raw_results[tool]["transfer__split__type2__split__M"]["FN"]
            + raw_results[tool]["origin__split__type2__split__M"]["FN"]
        )
        try:
            results[tool]["type2__split__M"]["prec."] = results[tool][
                "type2__split__M"
            ]["TP"] / (
                results[tool]["type2__split__M"]["TP"]
                + results[tool]["type2__split__M"]["FP"]
            )
        except:
            results[tool]["type2__split__M"]["prec."] = 0.00
        try:
            results[tool]["type2__split__M"]["rec."] = results[tool]["type2__split__M"][
                "TP"
            ] / (
                results[tool]["type2__split__M"]["TP"]
                + results[tool]["type2__split__M"]["FN"]
            )
        except:
            results[tool]["type2__split__M"]["rec."] = 0.00
        try:
            results[tool]["type2__split__M"]["f1."] = (
                2
                * results[tool]["type2__split__M"]["prec."]
                * results[tool]["type2__split__M"]["rec."]
                / (
                    results[tool]["type2__split__M"]["prec."]
                    + results[tool]["type2__split__M"]["rec."]
                )
            )
        except:
            results[tool]["type2__split__M"]["f1."] = 0.00

        results[tool]["type34__split__M"] = {}
        results[tool]["type34__split__M"]["TP"] = (
            raw_results[tool]["transfer__split__type34__split__M"]["TP"]
            + raw_results[tool]["origin__split__type34__split__M"]["TP"]
        )
        results[tool]["type34__split__M"]["FP"] = (
            raw_results[tool]["transfer__split__type34__split__M"]["FP"]
            + raw_results[tool]["origin__split__type34__split__M"]["FP"]
        )
        results[tool]["type34__split__M"]["FN"] = (
            raw_results[tool]["transfer__split__type34__split__M"]["FN"]
            + raw_results[tool]["origin__split__type34__split__M"]["FN"]
        )
        try:
            results[tool]["type34__split__M"]["prec."] = results[tool][
                "type34__split__M"
            ]["TP"] / (
                results[tool]["type34__split__M"]["TP"]
                + results[tool]["type34__split__M"]["FP"]
            )
        except:
            results[tool]["type34__split__M"]["prec."] = 0.00
        try:
            results[tool]["type34__split__M"]["rec."] = results[tool][
                "type34__split__M"
            ]["TP"] / (
                results[tool]["type34__split__M"]["TP"]
                + results[tool]["type34__split__M"]["FN"]
            )
        except:
            results[tool]["type34__split__M"]["rec."] = 0.00
        try:
            results[tool]["type34__split__M"]["f1."] = (
                2
                * results[tool]["type34__split__M"]["prec."]
                * results[tool]["type34__split__M"]["rec."]
                / (
                    results[tool]["type34__split__M"]["prec."]
                    + results[tool]["type34__split__M"]["rec."]
                )
            )
        except:
            results[tool]["type34__split__M"]["f1."] = 0.00

        results[tool]["type1__split__all"] = {}
        results[tool]["type1__split__all"]["TP"] = (
            results[tool]["type1__split__S"]["TP"]
            + results[tool]["type1__split__M"]["TP"]
        )
        results[tool]["type1__split__all"]["FP"] = (
            results[tool]["type1__split__S"]["FP"]
            + results[tool]["type1__split__M"]["FP"]
        )
        results[tool]["type1__split__all"]["FN"] = (
            results[tool]["type1__split__S"]["FN"]
            + results[tool]["type1__split__M"]["FN"]
        )
        try:
            results[tool]["type1__split__all"]["prec."] = results[tool][
                "type1__split__all"
            ]["TP"] / (
                results[tool]["type1__split__all"]["TP"]
                + results[tool]["type1__split__all"]["FP"]
            )
        except:
            results[tool]["type1__split__all"]["prec."] = 0.00
        try:
            results[tool]["type1__split__all"]["rec."] = results[tool][
                "type1__split__all"
            ]["TP"] / (
                results[tool]["type1__split__all"]["TP"]
                + results[tool]["type1__split__all"]["FN"]
            )
        except:
            results[tool]["type1__split__all"]["rec."] = 0.00
        try:
            results[tool]["type1__split__all"]["f1."] = (
                2
                * results[tool]["type1__split__all"]["prec."]
                * results[tool]["type1__split__all"]["rec."]
                / (
                    results[tool]["type1__split__all"]["prec."]
                    + results[tool]["type1__split__all"]["rec."]
                )
            )
        except:
            results[tool]["type1__split__all"]["f1."] = 0.00

        results[tool]["type2__split__all"] = {}
        results[tool]["type2__split__all"]["TP"] = (
            results[tool]["type2__split__S"]["TP"]
            + results[tool]["type2__split__M"]["TP"]
        )
        results[tool]["type2__split__all"]["FP"] = (
            results[tool]["type2__split__S"]["FP"]
            + results[tool]["type2__split__M"]["FP"]
        )
        results[tool]["type2__split__all"]["FN"] = (
            results[tool]["type2__split__S"]["FN"]
            + results[tool]["type2__split__M"]["FN"]
        )
        try:
            results[tool]["type2__split__all"]["prec."] = results[tool][
                "type2__split__all"
            ]["TP"] / (
                results[tool]["type2__split__all"]["TP"]
                + results[tool]["type2__split__all"]["FP"]
            )
        except:
            results[tool]["type2__split__all"]["prec."] = 0.00
        try:
            results[tool]["type2__split__all"]["rec."] = results[tool][
                "type2__split__all"
            ]["TP"] / (
                results[tool]["type2__split__all"]["TP"]
                + results[tool]["type2__split__all"]["FN"]
            )
        except:
            results[tool]["type2__split__all"]["rec."] = 0.00
        try:
            results[tool]["type2__split__all"]["f1."] = (
                2
                * results[tool]["type2__split__all"]["prec."]
                * results[tool]["type2__split__all"]["rec."]
                / (
                    results[tool]["type2__split__all"]["prec."]
                    + results[tool]["type2__split__all"]["rec."]
                )
            )
        except:
            results[tool]["type2__split__all"]["f1."] = 0.00

        results[tool]["type34__split__all"] = {}
        results[tool]["type34__split__all"]["TP"] = (
            results[tool]["type34__split__S"]["TP"]
            + results[tool]["type34__split__M"]["TP"]
        )
        results[tool]["type34__split__all"]["FP"] = (
            results[tool]["type34__split__S"]["FP"]
            + results[tool]["type34__split__M"]["FP"]
        )
        results[tool]["type34__split__all"]["FN"] = (
            results[tool]["type34__split__S"]["FN"]
            + results[tool]["type34__split__M"]["FN"]
        )
        try:
            results[tool]["type34__split__all"]["prec."] = results[tool][
                "type34__split__all"
            ]["TP"] / (
                results[tool]["type34__split__all"]["TP"]
                + results[tool]["type34__split__all"]["FP"]
            )
        except:
            results[tool]["type34__split__all"]["prec."] = 0.00
        try:
            results[tool]["type34__split__all"]["rec."] = results[tool][
                "type34__split__all"
            ]["TP"] / (
                results[tool]["type34__split__all"]["TP"]
                + results[tool]["type34__split__all"]["FN"]
            )
        except:
            results[tool]["type34__split__all"]["rec."] = 0.00
        try:
            results[tool]["type34__split__all"]["f1."] = (
                2
                * results[tool]["type34__split__all"]["prec."]
                * results[tool]["type34__split__all"]["rec."]
                / (
                    results[tool]["type34__split__all"]["prec."]
                    + results[tool]["type34__split__all"]["rec."]
                )
            )
        except:
            results[tool]["type34__split__all"]["f1."] = 0.00

        results[tool]["all__split__S"] = {}
        results[tool]["all__split__S"]["TP"] = (
            results[tool]["type2__split__S"]["TP"]
            + results[tool]["type34__split__S"]["TP"]
            + results[tool]["type1__split__S"]["TP"]
        )
        results[tool]["all__split__S"]["FP"] = (
            results[tool]["type2__split__S"]["FP"]
            + results[tool]["type34__split__S"]["FP"]
            + results[tool]["type1__split__S"]["FP"]
        )
        results[tool]["all__split__S"]["FN"] = (
            results[tool]["type2__split__S"]["FN"]
            + results[tool]["type34__split__S"]["FN"]
            + results[tool]["type1__split__S"]["FN"]
        )
        try:
            results[tool]["all__split__S"]["prec."] = results[tool]["all__split__S"][
                "TP"
            ] / (
                results[tool]["all__split__S"]["TP"]
                + results[tool]["all__split__S"]["FP"]
            )
        except:
            results[tool]["all__split__S"]["prec."] = 0.00
        try:
            results[tool]["all__split__S"]["rec."] = results[tool]["all__split__S"][
                "TP"
            ] / (
                results[tool]["all__split__S"]["TP"]
                + results[tool]["all__split__S"]["FN"]
            )
        except:
            results[tool]["all__split__S"]["rec."] = 0.00
        try:
            results[tool]["all__split__S"]["f1."] = (
                2
                * results[tool]["all__split__S"]["prec."]
                * results[tool]["all__split__S"]["rec."]
                / (
                    results[tool]["all__split__S"]["prec."]
                    + results[tool]["all__split__S"]["rec."]
                )
            )
        except:
            results[tool]["all__split__S"]["f1."] = 0.00

        results[tool]["all__split__M"] = {}
        results[tool]["all__split__M"]["TP"] = (
            results[tool]["type2__split__M"]["TP"]
            + results[tool]["type34__split__M"]["TP"]
            + results[tool]["type1__split__M"]["TP"]
        )
        results[tool]["all__split__M"]["FP"] = (
            results[tool]["type2__split__M"]["FP"]
            + results[tool]["type34__split__M"]["FP"]
            + results[tool]["type1__split__M"]["FP"]
        )
        results[tool]["all__split__M"]["FN"] = (
            results[tool]["type2__split__M"]["FN"]
            + results[tool]["type34__split__M"]["FN"]
            + results[tool]["type1__split__M"]["FN"]
        )
        try:
            results[tool]["all__split__M"]["prec."] = results[tool]["all__split__M"][
                "TP"
            ] / (
                results[tool]["all__split__M"]["TP"]
                + results[tool]["all__split__M"]["FP"]
            )
        except:
            results[tool]["all__split__M"]["prec."] = 0.00
        try:
            results[tool]["all__split__M"]["rec."] = results[tool]["all__split__M"][
                "TP"
            ] / (
                results[tool]["all__split__M"]["TP"]
                + results[tool]["all__split__M"]["FN"]
            )
        except:
            results[tool]["all__split__M"]["rec."] = 0.00
        try:
            results[tool]["all__split__M"]["f1."] = (
                2
                * results[tool]["all__split__M"]["prec."]
                * results[tool]["all__split__M"]["rec."]
                / (
                    results[tool]["all__split__M"]["prec."]
                    + results[tool]["all__split__M"]["rec."]
                )
            )
        except:
            results[tool]["all__split__M"]["f1."] = 0.00

        results[tool]["all__split__all"] = {}
        results[tool]["all__split__all"]["TP"] = (
            results[tool]["type2__split__all"]["TP"]
            + results[tool]["type34__split__all"]["TP"]
            + results[tool]["type1__split__all"]["TP"]
        )
        results[tool]["all__split__all"]["FP"] = (
            results[tool]["type2__split__all"]["FP"]
            + results[tool]["type34__split__all"]["FP"]
            + results[tool]["type1__split__all"]["FP"]
        )
        results[tool]["all__split__all"]["FN"] = (
            results[tool]["type2__split__all"]["FN"]
            + results[tool]["type34__split__all"]["FN"]
            + results[tool]["type1__split__all"]["FN"]
        )
        try:
            results[tool]["all__split__all"]["prec."] = results[tool][
                "all__split__all"
            ]["TP"] / (
                results[tool]["all__split__all"]["TP"]
                + results[tool]["all__split__all"]["FP"]
            )
        except:
            results[tool]["all__split__all"]["prec."] = 0.00
        try:
            results[tool]["all__split__all"]["rec."] = results[tool]["all__split__all"][
                "TP"
            ] / (
                results[tool]["all__split__all"]["TP"]
                + results[tool]["all__split__all"]["FN"]
            )
        except:
            results[tool]["all__split__all"]["rec."] = 0.00
        try:
            results[tool]["all__split__all"]["f1."] = (
                2
                * results[tool]["all__split__all"]["prec."]
                * results[tool]["all__split__all"]["rec."]
                / (
                    results[tool]["all__split__all"]["prec."]
                    + results[tool]["all__split__all"]["rec."]
                )
            )
        except:
            results[tool]["all__split__all"]["f1."] = 0.00

    fp = open("results_RQ2.json", "w")
    json.dump(results, fp, indent=4)
    fp.close()


if __name__ == "__main__":
    results_RQ2 = get_results_RQ2()
    refine_results_RQ2(results_RQ2)
