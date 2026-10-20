#!/bin/bash

HQC_DIR="$HOME/hqc-hom-test"

gcc \
-I"$HQC_DIR/src/ref/hqc-1" \
-I"$HQC_DIR/src/ref" \
-I"$HQC_DIR/src/common" \
-I"$HQC_DIR/src/common/hqc-1" \
-I"$HQC_DIR/lib/fips202" \
"$HOME/hqc-hybrid-encryption/src/test_double_kem_xor.c" \
"$HQC_DIR/src/common/kem.c" \
"$HQC_DIR/src/ref/hqc.c" \
"$HQC_DIR/src/ref/parsing.c" \
"$HQC_DIR/src/ref/reed_muller.c" \
"$HQC_DIR/src/ref/reed_solomon.c" \
"$HQC_DIR/src/ref/vector.c" \
"$HQC_DIR/src/ref/gf.c" \
"$HQC_DIR/src/ref/gf2x.c" \
"$HQC_DIR/src/common/code.c" \
"$HQC_DIR/src/common/fft.c" \
"$HQC_DIR/src/common/crypto_memset.c" \
"$HQC_DIR/src/common/symmetric.c" \
"$HQC_DIR/lib/fips202/fips202.c" \
-o "$HOME/hqc-hybrid-encryption/test_double_kem_xor"

echo "Build complete."
echo "Run with:"
echo "./test_double_kem_xor"
