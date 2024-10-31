import json
import os
import shutil

import pandas as pd

fp = open(
    "E:\\workspace\\AntMan-opensource.github.io\\empirical\\dataset\\detected_repo_list.json"
)
repo_list = json.load(fp)
fp.close()

datas = []

for repo in repo_list:
    if repo_list[repo] == {}:
        data = {
            "detect_dir": f"./target_repo_cache/{repo}-newest",
            "work_dir": "path/to/joern",
        }
        datas.append(data)
    else:
        for tag in repo_list[repo]:
            data = {
                "detect_dir": f"./target_repo_cache/{repo}-{tag}",
                "work_dir": "path/to/joern",
            }
            datas.append(data)

os.system("echo %cd%")
vuddy_df = pd.DataFrame(datas)
vuddy_df.to_csv("targetList.csv", index=False)
