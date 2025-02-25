# Homomorphic Encryption Performance Comparison

This repository contains a series of tests comparing the performance of four popular homomorphic encryption schemes: Paillier, CKKS, BGV, and BFV. The tests measure the encryption and decryption times, as well as the memory consumption (in terms of object sizes) for various input sizes.

## Key Features

- **Encryption Schemes Tested:**
  - **Paillier**
  - **CKKS**
  - **BGV**
  - **BFV**

- **Metrics:**
  - Encryption time (milliseconds)
  - Decryption time (milliseconds)
  - Plaintext size (in bytes)
  - Ciphertext size (in bytes)

- **Libraries Used:**
  - Paillier: [phe](https://github.com/wolfeidau/paillier)
  - CKKS: [tenseal](https://github.com/OpenMined/TenSEAL)
  - BGV and BFV: [Pyfhel](https://github.com/ibarrond/pyfhel)

## Requirements

To run the tests, the following libraries are required:

- `phe` (for Paillier encryption)
- `tenseal` (for CKKS encryption)
- `Pyfhel` (for BGV and BFV encryption)
- `numpy` (for handling arrays)
- `time`, `random`, `sys` (standard Python libraries)

You can install the necessary dependencies using `pip`:

```bash
pip install phe numpy tenseal Pyfhel
```

## Running the Tests

To test the encryption schemes, simply run the Python script:

```bash
python test_encryption.py
```

This will execute the encryption and decryption for a range of input sizes and display the results in a formatted table.

