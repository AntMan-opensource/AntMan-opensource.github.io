# Recurring Vulnerability Detection: How Far Are We?

## News

- [2024-10-20]🚀🚀🚀We have successfully detected 4,593 recurring vulnerabilities, with 307 confirmed by developers, and identified 73 new 0-day vulnerabilities across 15 projects, receiving 5 CVE identifiers.

## AntMan

With the rapid development of open-source software, code reuse has become a common practice to accelerate development. However, it leads to inheritance from the original vulnerability, which recurs at the reusing projects, known as recurring vulnerabilities (RVs). Traditional general-purpose vulnerability detection approaches struggle with scalability and adaptability, while learning-based approaches are often constrained by limited training datasets and are less effective against unseen vulnerabilities. Though specific recurring vulnerability detection (RVD) approaches have been proposed, their effectiveness across various RV characteristics remains unclear.

In this paper, we conduct a large-scale empirical study using a newly constructed RV dataset containing 4,569 RVs, achieving a 953% expansion over prior RV datasets. Our study analyzes the characteristics of RVs, evaluates the effectiveness of the state-of-the-art RVD approaches, and investigates the root causes of false positives and false negatives, yielding key insights. Inspired by these insights, we design AntMan, a novel RVD approach that identifies both explicit and implicit call relations with modified functions, then employs inter-procedural taint analysis and intra-procedural dependency slicing within those functions to generate comprehensive signatures, and finally incorporates a flexible matching to detect RVs. Our comprehensive evaluation has demonstrated the effectiveness, generality and practical usefulness in RVD. Notably, AntMan has successfully detected 4,593 recurring vulnerabilities, with 307 confirmed by developers, and identified 73 new 0-day vulnerabilities across 15 projects, receiving 5 CVE identifiers.



The paper has been submitted to ISSTA 2025.  



This page lists the supplementary materials including the dataset, source code and reproducing scripts on our paper.



## Empirical Study

### Setup

- Ground Truth Construction

​	TBD

- RVD Approaches Selection

​	TBD

### RQ1 Characteristic Analysis of RVs.

TBD

### RQ2 Effectiveness Evaluation of RVD. 

TBD

### RQ3 FP/FN Analysis of RVD.

TBD



## AntMan

### **Environment Setup:**

TBD

### Methodology Implementation

TBD

### Evaluation

#### RQ4 Effectiveness Evaluation

TBD

#### RQ5 Ablation Study

TBD

#### RQ6 Parameter Sensitivity Analysis

TBD

#### RQ7 Generality Evaltion

TBD

#### RQ8 0-day Detection Capability

TBD

#### RQ9 Efficiency Evaluation

TBD

#### RQ10 Usefulness Evaluation

TBD

