import json

import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.family"] = "Times New Roman"


def generate_data():
    with open("icpc_fix.json", "r") as fr:
        vul_threshols = json.load(fr)
    precision = np.array(
        [
            vul_threshols["1"]["precision"],
            vul_threshols["2"]["precision"],
            vul_threshols["3"]["precision"],
            vul_threshols["4"]["precision"],
            vul_threshols["5"]["precision"],
            vul_threshols["6"]["precision"],
            vul_threshols["7"]["precision"],
            vul_threshols["8"]["precision"],
            vul_threshols["9"]["precision"],
        ]
    )
    recall = np.array(
        [
            vul_threshols["1"]["recall"],
            vul_threshols["2"]["recall"],
            vul_threshols["3"]["recall"],
            vul_threshols["4"]["recall"],
            vul_threshols["5"]["recall"],
            vul_threshols["6"]["recall"],
            vul_threshols["7"]["recall"],
            vul_threshols["8"]["recall"],
            vul_threshols["9"]["recall"],
        ]
    )
    f1 = 2 * (precision * recall) / (precision + recall + 1e-5)
    return precision, recall, f1


thresholds = np.arange(0.1, 1.0, 0.1)

fig, ax = plt.subplots(figsize=(5, 5))

precision, recall, f1 = generate_data()
max_f1_index = np.argmax(f1)
max_f1 = f1[max_f1_index]
max_f1_threshold = thresholds[max_f1_index]

ax.plot(
    thresholds, precision, label="Precision", marker="s", linewidth=2, color="#89AA7B"
)
ax.plot(thresholds, recall, label="Recall", marker="^", linewidth=2, color="#7789B7")
ax.plot(thresholds, f1, label="F1 Score", marker="o", linewidth=2, color="#EB6969")
ax.scatter(max_f1_threshold, max_f1, color="#F46F43")

plt.plot(
    [max_f1_threshold, max_f1_threshold],
    [max_f1, 0],
    color="grey",
    linestyle="--",
    linewidth=2,
)
ax.text(
    max_f1_threshold - 0.02,
    max_f1 + 0.05,
    f" Max F1={max_f1:.2f}",
    color="#EB6969",
    fontweight="bold",
    fontsize=15,
)

ax.set_xlabel("Threshold", fontsize=14)
ax.legend(loc="lower right", fontsize=14)
ax.grid(True)
ax.set_xticks(np.arange(0.1, 1.0, 0.1))
ax.set_ylim(0, 1)
ax.tick_params(axis="both", labelsize=14)

plt.tight_layout()
pdf_path = "./icpc_fix.pdf"
plt.savefig(pdf_path)

plt.show()
