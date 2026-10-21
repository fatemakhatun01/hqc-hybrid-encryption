# Build Scripts

This directory contains helper scripts for compiling the HQC-based hybrid encryption experiments.

## Prerequisite

The HQC reference implementation should already be available on the system.

In the development environment used for this project, the HQC source directory is:

```text
~/hqc-hom-test

and this repository is located at: ~/hqc-hybrid-encryption

Run the experiment with:
./test_double_kem_xor

The expected final output is:
SUCCESS: recovered value matches m1 XOR m2

Notes
The build script compiles the source file:
src/test_double_kem_xor.c

against the HQC reference implementation located in:
~/hqc-hom-test

If the HQC directory is stored somewhere else, update the HQC_DIR variable inside the script before compiling.

The compiled executable itself is not intended to be stored in GitHub. Only the source code, scripts, documentation, and experiment outputs are maintained in the repository.
