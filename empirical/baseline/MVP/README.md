# MVP
MVP is an approach for scalable and accurate vulnerable code clone detection. Principles are discussed in
[MVP: Detecting Vulnerabilities using Patch-Enhanced Vulnerability Signatures](https://chenbihuan.github.io/paper/sec20-xiao-mvp.pdf), which was published in 29th
Usenix Security Symposium (sec'20).

We reproduced this tool as our baseline.

## How to Use
### Requirements

* **python**: 3.11.8

* **joern**: 2.260

  The installation process for Joern can be found at https://docs.joern.io/installation.

* **tree-sitter**: 0.22.6

  The installation process for tree-sitter can be found at https://tree-sitter.github.io/tree-sitter/

- Other relevant dependent packages listed in [requirements.txt](./requirements.txt)

To setup, just run:
```
pip install -r requirements.txt
```

### Running MVP

※ If you have problems related to path information, try testing with absolute paths.

### Signature Generation


 - After install the joern, specify the directory paths of joern in [config.py](./src/config.json).
 - Store the patch for the CVE that needs to be determined [CVEcommit](./src/commit_info), the path need to be the format as "CVE.txt". Clone the relevant repositories into the a diretory and record the related information which include **the CVE-ID corresponding to the patch file, the absolute path to the file storing GitHub commit content, the absolute path to the directory of the GitHub repository corresponding to the CVE and the absolute path to the directory of joern-cli** into the [CVEdataset.csv](./src/CVEdataset.csv) 
 The CVE patches involved in this experiment are stored in [CVEcommit](./src/CVEcommit), and you only need to clone the repositories listed in [repositories list](https://github.com/AntMan-opensource/AntMan-opensource.github.io/tree/main/empirical/dataset/detected_repo_list.json).
 - Execute [gen_fingerprint_multi.py](./src/gen_fingerprint_multi.py) to generate the signatures of the patch which you collected.

 ```
 python gen_fingerprint_multi.py
 ```
 - Extract the modified file into the [vulFile](./src/vulFile) and record the starting and ending lines of the patch modification function, as well as the file information in [sagaMulti.json](./src/infoFile/sagaMulti.json)

### Detection

 -  Record the related information which include **the absolute path of detected repository and the absolute path to the directory of joern-cli** into the [targetList.csv](./src/targetList.csv)
 - Execute [detection.py](./src/detection.py) to evaluate target vulnerable versions in open-source Java software, the result will be output to resultMultiSnippetVersion.txt.
 ```
 python detection.py
 ```