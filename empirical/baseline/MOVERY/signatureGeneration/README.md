# MOVERY

MOVERY is an approach for scalable and accurate vulnerable code clone detection. Principles are discussed in
[MOVERY: A Precise Approach for Modified Vulnerable Code Clone Discovery from Modified Open-Source Software Components](https://www.usenix.org/system/files/sec22-woo.pdf), which was published in 31st Usenix Security Symposium (sec'22).

We reproduced the signature generation module of this approach and run the detect module of this approach released on [docker](https://hub.docker.com/r/seunghoonwoo/movery-public)

## How to use
### Requirements

* ***Linux***: MVP is designed to work on any of the operating systems. However, currently, this repository only focuses on the Linux environment.
* ***Git***
* ***Python 3***
* **[joern](https://docs.joern.io/installation)**
* [**ctags**](https://github.com/universal-ctags/ctags) 

Our utilized versions: Python 3.11.8, joern  2.260, ctags 5.9.0 and some other elevant dependent packages listed in [requirements.txt](./requirements.txt) on Ubuntu 18.04.
### Running MOVERY 

※ If you have problems related to path information, try testing with absolute paths.

### Signature generation
- After install the joern and ctags, specify the directory paths of joern and ctags in [config.py](./config.py).
- clone the CVE mentioned in [cve_list.json](cve_list.json) corresponding repositories from GitHub and store it in the *signature_repo_cache* directory.
- Execute [signature_generation.py](./signature_generation.py) to generate the signatures of the patch which you collected. The output signature will be stored in the *dataset*. The description of the signature is shown in its paper.
```
 python signature_generation.py
```
### Detection
- Just followed the [instruction](https://github.com/WOOSEUNGHOON/MOVERY-public) to run the detection code in [docker](https://hub.docker.com/r/seunghoonwoo/movery-public)