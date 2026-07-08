[![Browse the corpus](https://img.shields.io/badge/Browse%20the%20corpus-0891B2?style=flat&logo=readthedocs&logoColor=white)](https://byteray-ai.github.io/drift-corpus)
[![Discord](https://img.shields.io/badge/Discord-Join%20our%20server-5865F2?logo=discord&logoColor=white)](https://discord.gg/46ndug98k)

# The Drift Corpus: Ring 0

**Drift Corpus** is the definitive, open-source repository of Windows Kernel patch diffs. 

These artifacts are produced using **Drift Agent**, ByteRay's automatic reverse engineering engine and part of the Argus-Systems platform. With Drift, we have successfully mapped, analyzed, and annotated Windows kernel vulnerabilities patched by Microsoft. The collection currently covers entries from 2026 (240+), with additional entries being added over time.


## 🚀 Community

As once said by Derek Soeder, **we left the exploitation of these vulnerabilities to the reader**. Join our [Discord](https://discord.gg/46ndug98k) for collaboration on further PoC/exploit development.

## ⚠️ Binary Distribution

**We do not distribute Microsoft binaries.** This repository contains only the JSON metadata, analysis, and assembly diffs. To reconstruct the full research environment and download the actual `.sys`, `.exe`, and `.dll` files referenced in this corpus, you can use the KB number listed in the `metadata.json` with [PatchPair](https://github.com/ByteRay-AI/patchpair) project.

## 📂 Dataset Structure

Every patched vulnerability in this corpus is stored in its own directory, containing a file named (e.g. `afd-report-20260626-131300.json`) and a comprehensive schema.

Each JSON entry contains:

* **`binaries`**: High-level similarity scores, matched/unmatched block counts, and file identifiers (e.g., `afd_unpatched.sys` and `afd_patched.sys`).
* **`changed_functions`**: Granular breakdowns of modified functions, including similarity scores, behavior changes, and raw assembly diffs. It explicitly flags if a change is `security_relevant` or merely `cosmetic`.
* **`security_findings`**: The core analysis. Drift autonomously maps out the vulnerability class, call chains, exploit primitives (e.g., Kernel pool use-after-free), and precise trigger conditions.
* **`debugging_aids`**: Ready-to-use WinDbg offsets, including recommended breakpoints, memory watch targets, and expected crash observations to help you reproduce the flaw immediately.
* **`summary`**: A high-level, human-readable overview of the patch and the root cause.

## 📖 How to Cite Us

If you use the Drift Corpus in your vulnerability research, academic papers, or AI training datasets, please cite ByteRay and the engine engine using the following format:

**Text Citation:**
> ByteRay (2026). *The Drift Corpus: Ring 0*. ByteRay Ltd. Retrieved from https://github.com/byteray/drift-corpus.

**BibTeX:**
```bibtex
@misc{byteray_drift_2026,
  author = {ByteRay Ltd.},
  title = {The Drift Corpus: Ring 0},
  year = {2026},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\url{[https://github.com/ByteRay-AI/drift-corpus](https://github.com/ByteRay-AI/drift-corpus)}},
  note = {Generated via Argus-Systems Drift Automatic Reverse Engineering Engine}
}
