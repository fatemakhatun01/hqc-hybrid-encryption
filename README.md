# HQC-Based Hybrid Encryption

This repository contains the implementation associated with the research work:

**HQC-Based Hybrid Encryption: Implementation of XOR and Modular DEM Variants with CPA Security Discussion**

Authors:
- Fatema Khatun
- Kirill Morozov

Department of Computer Science and Engineering  
University of North Texas

## Overview

This project investigates hybrid encryption using HQC-KEM together with lightweight Data Encapsulation Mechanisms (DEMs).

The repository contains implementations for:

- HQC-KEM key generation, encapsulation, and decapsulation
- Verification of matching 32-byte shared secrets
- XOR-based KEM-DEM encryption
- Modular DEM using the prime p = 4294967291
- Two independent HQC encapsulations under the same public key
- XOR combination of DEM components
- Recovery of the plaintext relation m1 XOR m2
- Experimental direct HQC ciphertext addition

## Source Files

### `test_kem_flow.c`

Verifies the basic HQC-KEM workflow:

- key generation
- encapsulation
- decapsulation
- shared-secret equality

### `test_hybrid_kem_dem.c`

Implements the XOR-based hybrid KEM-DEM construction.

Encryption:

DEM = m XOR ss

Decryption:

m = DEM XOR ss

### `test_hybrid_modp.c`

Implements the modular DEM construction using:

p = 4294967291

Encryption:

c_i = (m_i + ss_i) mod p

Decryption:

m_i = (c_i - ss_i) mod p

### `test_double_kem_xor.c`

Implements two independent HQC encapsulations under the same public key.

The DEM components are:

d1 = m1 XOR ss1

d2 = m2 XOR ss2

The public combination is:

d_combined = d1 XOR d2

After decapsulation:

d_combined XOR ss1 XOR ss2 = m1 XOR m2

Therefore, the construction supports a limited XOR-style message-level operation without directly modifying the internal HQC ciphertext components.

### `test_addition.c`

Contains experimental work involving direct manipulation or combination of HQC ciphertext components. This experiment was used to study the effect of accumulated error and decoding limitations.

## Repository Structure

```text
src/
    Source code for experiments

results/
    Experimental outputs

docs/
    Implementation and security notes

scripts/
    Build scripts


## Security Scope

The constructions are studied at the chosen-plaintext attack (CPA) level.

The XOR-based and modular DEM variants are malleable and do not provide ciphertext integrity. Therefore, the current implementation should not be considered chosen-ciphertext secure.

## Dependency

This project uses the HQC reference implementation as the underlying Key Encapsulation Mechanism.

Official HQC project:

https://pqc-hqc.org/

## Disclaimer

This repository is intended for academic research and educational purposes. It is not production cryptographic software.
