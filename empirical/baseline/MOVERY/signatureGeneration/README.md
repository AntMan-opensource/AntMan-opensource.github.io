# MOVERY

MOVERY is an approach for scalable and accurate vulnerable code clone detection. Principles are discussed in
[MOVERY: A Precise Approach for Modified Vulnerable Code Clone Discovery from Modified Open-Source Software Components](https://www.usenix.org/system/files/sec22-woo.pdf), which was published in 31st Usenix Security Symposium (sec'22).

We reproduced the signature generation module of this approach and run the detect module of this approach released on [docker](https://hub.docker.com/r/seunghoonwoo/movery-public)

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

### Running MOVERY 

※ If you have problems related to path information, try testing with absolute paths.

### Signature Generation
- After install the joern and ctags, specify the directory paths of joern and ctags in [config.py](./config.py).
- Clone the CVE mentioned in [cve_list.json](cve_list.json) corresponding repositories from GitHub and store it in the *signature_repo_cache* directory.
- Execute [signature_generation.py](./signature_generation.py) to generate the signatures of the patch which you collected. The output signature will be stored in the *dataset*. The description of the signature is shown in its paper.
```
 python signature_generation.py
```
### Detection
- Just followed the [instruction](https://github.com/WOOSEUNGHOON/MOVERY-public) to run the detection code in [docker](https://hub.docker.com/r/seunghoonwoo/movery-public)