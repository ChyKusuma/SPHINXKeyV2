# SPHINXKeyV2

## Introduction

This project is dedicated to the world community as an Open-source Post-quantum blockchain layer 1 project, means anyone can join and contribute based on his/ her passion and skills. SPHINX is a blockchain protocol designed to provide secure and scalable solutions in the post-quantum era.

This repository contains code for the SPHINXKey project, which is a `Merged Hybrid Key pair` and `generating Address` module for the SPHINX blockchain framework.

## Components

This code is alternative for [SPHINXHKey](https://github.com/SPHINX-HUB-ORG/SPHINXKey) as further consideration.

### Namespaces:

- SPHINXHybridKey: A namespace that contains the definition of the HybridKeypair structure, which represents a hybrid cryptographic key pair.

- SPHINXHash: A namespace that contains the definitions of two hash functions: `SPHINX_256` and `RIPEMD_160`. These functions take a vector of unsigned characters `(std::vector<unsigned char>)` as input and return a string representing the hashed value.

### Base58 Encoding:

- The code defines a static constant string `base58_chars`, which contains characters used for Base58 encoding. Base58 is a binary-to-text encoding scheme commonly used for encoding in Bitcoin addresses and other cryptographic data, we needed this only to produce shorter address and for human readability.

- The function `EncodeBase58` takes a vector of unsigned characters `(std::vector<unsigned char>)` as input and returns the Base58 encoded string.

### Key Generation and Hybrid Key Pair Handling:
- The code provides several functions for generating and handling hybrid key pairs, which are composed of both `Curve448` and `Kyber1024` key pairs.

- The SPHINXKey namespace contains functions for generating public and private keys, merging public and private keys, converting keys to strings, and generating smart contract addresses based on public keys and contract names.

### Key Generation and Key Exchange Functions:
- `generate_hybrid_keypair`: This function generates a hybrid key pair by creating `Curve448` and `Kyber1024` key pairs and then merging them into a single key pair.

- `generate_and_perform_key_exchange`: This function demonstrates the process of generating a hybrid key pair, performing a key exchange using `X448` and `Kyber1024` KEM (Key Encapsulation Mechanism), and encrypting and decrypting a message using `Kyber1024 PKE` (Public Key Encryption).

### Private and Public Key Merging Functions:
The code contains two functions named `mergePrivateKeys` and `mergePublicKeys`, both of which take `Curve448` and `Kyber1024` private/public keys as input, merge them together, and then hash the merged keys using the `SPHINX_256` hash function.

### Printing and Address Generation Functions:

- `printKeyPair`: This function takes a name, private key, and public key as input, prints them, and generates a contract address based on the public key and a contract name.

### Miscellaneous:
- The code defines several constants related to key sizes and hybrid key structures.

This code provides a set of functions and structures to support hybrid key generation, key exchange, encryption, decryption, and other cryptographic operations.

#### The interaction and collaboration between Key.cpp and [SPHINXHybridKey](https://github.com/SPHINX-HUB-ORG/SPHINXHybridKeyV2) can be summarized as follows:

1. **SPHINXKey Namespace** interacts with the **SPHINXHybridKey Namespace** by calling the function `generate_hybrid_keypair` from the `SPHINXHybridKey` namespace. This function generates the hybrid keypair and its corresponding private and public keys.

2. The function `SPHINXKey::generateAddress` uses the `SPHINXHybridKey::SPHINXHash::SPHINX_256` function to hash the public key and generate an address based on the hash. This address is used for smart contract identification.

3. In `SPHINXHybridKey::generate_hybrid_keypair`, Kyber1024 and X448 keypairs are generated. The function also derives a master private key and chain code using HMAC-SHA512 from a seed value and then derives private and public keys from the master key and chain code using HMAC-SHA512.

4. The `SPHINXHybridKey` namespace provides functions to encrypt and decrypt messages using Kyber1024 for KEM (Key Encapsulation Mechanism).

5. The `SPHINXHybridKey::performX448KeyExchange` function performs the X448 key exchange.

6. The `SPHINXHybridKey` namespace also includes functions to encapsulate and decapsulate shared secrets using the hybrid KEM, combining the results of Kyber1024 and X448.

**Combined Usage**:
The combined usage of `SPHINXKey` and `SPHINXHybridKey` allows for the generation of secure hybrid keypairs that leverage the strengths of both Kyber1024 and X448 cryptographic algorithms. The hybrid keypairs can be used for various cryptographic purposes, including encryption, decryption, and key exchange, making it a versatile and robust cryptographic solution.


The interaction between Key.cpp and Hybrid_key.hpp involves calling functions defined in Hybrid_key.hpp from Key.cpp to perform various operations related to hybrid key generation, key exchange, address generation, and public key calculation. Hybrid_key.hpp provides the necessary functions and data structures to support these operations, and Key.cpp utilizes them to implement the desired functionality.



### Note

Every code in the repository is a part of the SPHINX blockchain algorithm, which is currently in development and not fully integrated or extensively tested for functionality. The purpose of this repository is to provide a framework and algorithm for the digital signature scheme in the SPHINX blockchain project.

As the project progresses, further updates and enhancements will be made to ensure the code's stability and reliability. We encourage contributors to participate in improving and refining the SPHINXBlock algorithm by submitting pull requests and providing valuable insights.

We appreciate your understanding and look forward to collaborative efforts in shaping the future of the SPHINX blockchain project.


## Getting Started
To get started with the SPHINX blockchain project, follow the instructions below:

1. Clone the repository: `git clone https://github.com/ChyKusuma/SPHINXKey.git`
2. Install the necessary dependencies (List the dependencies or provide a link to the installation guide).
3. Explore the codebase to understand the project structure and components.
4. Run the project or make modifications as needed.


## Contributing
We welcome contributions from the developer community to enhance the SPHINX blockchain project. If you are interested in contributing, please follow the guidelines below:

1. Fork the repository on GitHub.
2. Create a new branch for your feature or bug fix: `git checkout -b feature/your-feature-name` or `git checkout -b bugfix/your-bug-fix`.
3. Make your modifications and ensure the code remains clean and readable.
4. Write tests to cover the changes you've made, if applicable.
5. Commit your changes: `git commit -m "Description of your changes"`.
6. Push the branch to your forked repository: `git push origin your-branch-name`.
7. Open a pull request against the main repository, describing your changes and the problem it solves.
8. Insert your information (i.e name, email) in the authors space.

## License
Specify the license under which the project is distributed (MIT License).

## Contact
If you have any questions, suggestions, or feedback regarding the SPHINX blockchain project, feel free to reach out to us at [sphinxfounders@gmail.com](mailto:sphinxfounders@gmail.com).
