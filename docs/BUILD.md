# Build Instructions

This project is designed to be compiled against the HQC reference implementation.

## Environment

The implementation was tested on:

- Ubuntu Linux
- GCC
- HQC reference implementation
- FIPS202 implementation included with HQC

## HQC Dependency

The HQC reference implementation should be available separately.

The experiment files in this repository are located in:

src/

## Example Compile Command

The following command can be used to compile the two-ciphertext XOR experiment from the HQC project directory:

```bash
gcc \
-I./src/ref/hqc-1 \
-I./src/ref \
-I./src/common \
-I./src/common/hqc-1 \
-I./lib/fips202 \
experiments/test_double_kem_xor.c \
src/common/kem.c \
src/ref/hqc.c \
src/ref/parsing.c \
src/ref/reed_muller.c \
src/ref/reed_solomon.c \
src/ref/vector.c \
src/ref/gf.c \
src/ref/gf2x.c \
src/common/code.c \
src/common/fft.c \
src/common/crypto_memset.c \
src/common/symmetric.c \
lib/fips202/fips202.c \
-o experiments/test_double_kem_xor
