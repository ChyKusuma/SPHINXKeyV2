/*
 *  Copyright (c) (2023) SPHINX_ORG
 *  Authors:
 *    - (C kusuma) <thekoesoemo@gmail.com>
 *      GitHub: (https://github.com/chykusuma)
 *  Contributors:
 *    - (Contributor 1) <email1@example.com>
 *      Github: (https://github.com/yourgit)
 *    - (Contributor 2) <email2@example.com>
 *      Github: (https://github.com/yourgit)
 */


/////////////////////////////////////////////////////////////////////////////////////////////////////////
// This code is a part of the SPHINXKey namespace, which provides functions related to the SPHINX (Sphinx-Hybrid Key) cryptographic scheme. The main functionalities include generating SPHINX key pairs, extracting SPHINX public and private keys from a hybrid key pair, calculating the SPHINX public key from the private key, and generating a smart contract address based on the SPHINX public key and a contract name. Let's break down the code and explain each part in detail:

// Type Aliases and Constants:
    // The code defines two type aliases SPHINXPubKey and SPHINXPrivKey to represent SPHINX public and private keys, respectively. Additionally, it defines a constant SPHINX_PUBLIC_KEY_LENGTH which is the size of the SPHINX public key, calculated as the sum of the Kyber1024 public key size and the X448 public key size.

// calculatePublicKey Function:
    // This function takes the SPHINX private key as input and calculates the corresponding SPHINX public key. It creates a vector of bytes to store the public key, then calls a hypothetical function calculate_sphinx_public_key, which is assumed to be available externally to calculate the public key. The function returns the computed public key as a vector.

// extractSPHINXPublicKey and extractSPHINXPrivateKey Functions:
    // These functions are used to extract the SPHINX public and private keys, respectively, from a hybrid key pair (HybridKeypair struct). They simply return the corresponding components from the merged_key member of the HybridKeypair structure.

// generateAddress Function:
    // This function generates a smart contract address based on the SPHINX public key and a contract name. It uses the SPHINXHash::SPHINX_256 function (assumed to be available) to hash the SPHINX public key. The function then concatenates the contract name and the hashed public key to create a contract identifier. Finally, the function returns the contract identifier as the smart contract address.

// printKeyPair Lambda Function:
    // This lambda function is defined inside the generateAddress function. It takes a hybrid key pair as input and prints the merged public key and the smart contract address generated from that public key using the generateAddress function.

// generate_hybrid_keypair Function:
    // This function calls the SPHINXHybridKey::generate_hybrid_keypair function from the SPHINXHybridKey namespace (assumed to be available externally). It generates a hybrid key pair using the Kyber1024, X448, and PKE schemes. Then, it returns the generated hybrid key pair.

// The SPHINXKey namespace provides a set of utility functions to work with the SPHINX cryptographic scheme and interacts with other functions available in the SPHINXHybridKey namespace to generate a hybrid key pair and perform key exchange and encryption operations using the Kyber1024, X448, and PKE schemes.
////////////////////////////////////////////////////////////////////////////////////////////////////////


#include <string>
#include <vector>
#include <cstring>
#include <utility>
#include <iostream>

#include "Hybrid_key.hpp"
#include "Hash.hpp"
#include "Key.hpp"


namespace SPHINXKey {
    
    // Constants
    constexpr size_t CURVE448_PRIVATE_KEY_SIZE = 56;
    constexpr size_t CURVE448_PUBLIC_KEY_SIZE = 56;
    constexpr size_t CURVE448_SHARED_SECRET_SIZE = 56;
    constexpr size_t KYBER1024_PUBLIC_KEY_LENGTH = 800;
    constexpr size_t KYBER1024_PRIVATE_KEY_LENGTH = 1632;
    constexpr size_t KYBER1024_CIPHERTEXT_LENGTH = 1088;
    constexpr size_t KYBER1024_SHARED_SECRET_LENGTH = 32;
    constexpr size_t KYBER1024_PKE_PUBLIC_KEY_LENGTH = 800;
    constexpr size_t KYBER1024_PKE_PRIVATE_KEY_LENGTH = 1632;
    constexpr size_t KYBER1024_PKE_CIPHERTEXT_LENGTH = 1088;

    // Define an alias for the merged public key as SPHINXPubKey
    using SPHINXPubKey = std::vector<unsigned char>;

    // Define an alias for the merged private key as SPHINXPrivKey
    using SPHINXPrivKey = std::vector<unsigned char>;

    // Define value of SPHINXPubKey length
    constexpr size_t SPHINX_PUBLIC_KEY_LENGTH = KYBER1024_PUBLIC_KEY_LENGTH + CURVE448_PUBLIC_KEY_SIZE;

    // Function to calculate the SPHINX public key from the private key
    SPHINXKey::SPHINXPubKey calculatePublicKey(const SPHINXKey::SPHINXPrivKey& privateKey) {
        // The length of the Kyber1024 public key
        constexpr size_t KYBER_PUBLIC_KEY_LENGTH = SPHINXKey::KYBER1024_PUBLIC_KEY_LENGTH;

        // Calculate the SPHINX public key by extracting the Kyber1024 public key from the merged private key
        SPHINXKey::SPHINXPubKey sphinxPublicKey(privateKey.begin() + KYBER_PUBLIC_KEY_LENGTH, privateKey.end());

        return sphinxPublicKey;
    }

    // Function to extract the SPHINX public key from the hybrid keypair
    SPHINXPubKey extractSPHINXPublicKey(const SPHINXHybridKey& hybridKeyPair) {
        return hybridKeyPair.merged_key.kyber_public_key;
    }

    // Function to extract the SPHINX private key from the hybrid keypair
    SPHINXPrivKey extractSPHINXPrivateKey(const SPHINXHybridKey& hybridKeyPair) {
        return hybridKeyPair.merged_key.kyber_private_key;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    // Function to generate the hybrid keypair using functions from "hybrid_key.cpp"
    // The function first generates a Kyber1024 keypair for KEM, then generates an X448 keypair, and 
    // finally generates a PKE keypair. The private and public keys are then derived from the master 
    // private key and chain code using HMAC-SHA512. The generated hybrid keypair includes the Kyber1024
    // public and private keys, as well as the X448 public and private keys, all combined into a single 
    // merged key pair.
    //////////////////////////////////////////////////////////////////////////////////////////////////
    SPHINXHybridKey::HybridKeypair generate_hybrid_keypair() {
        // Call the original function from "hybrid_key.cpp"
        SPHINXHybridKey::HybridKeypair hybridKeyPair = SPHINXHybridKey::generate_hybrid_keypair();

        // Merge the public and private keys obtained from Kyber1024 and X448 key generation
        SPHINXKey::SPHINXPrivKey mergedPrivateKey;
        mergedPrivateKey.insert(mergedPrivateKey.end(), hybridKeyPair.merged_key.kyber_private_key.begin(), hybridKeyPair.merged_key.kyber_private_key.end());
        mergedPrivateKey.insert(mergedPrivateKey.end(), hybridKeyPair.x448_key.second.begin(), hybridKeyPair.x448_key.second.end());

        SPHINXKey::SPHINXPubKey mergedPublicKey;
        mergedPublicKey.insert(mergedPublicKey.end(), hybridKeyPair.merged_key.kyber_public_key.begin(), hybridKeyPair.merged_key.kyber_public_key.end());
        mergedPublicKey.insert(mergedPublicKey.end(), hybridKeyPair.x448_key.first.begin(), hybridKeyPair.x448_key.first.end());

        hybridKeyPair.merged_key.kyber_private_key = mergedPrivateKey;
        hybridKeyPair.merged_key.kyber_public_key = mergedPublicKey;

        return hybridKeyPair; // Return the hybrid_keypair object
    }

    // Function to generate and perform a key exchange
    SPHINXHybridKey::HybridKeypair generate_and_perform_key_exchange() {
        // Generate the hybrid keypair
        SPHINXHybridKey::HybridKeypair hybrid_keypair = generate_hybrid_keypair();

        // Perform the key exchange using Kyber1024 KEM
        std::vector<uint8_t> encapsulated_key;
        std::string shared_secret = encapsulateHybridSharedSecret(hybrid_keypair, encapsulated_key);

        // Return the hybrid keypair containing the exchanged keys
        return SPHINXHybridKey::HybridKeypair;
    }

    // Function to calculate the SPHINX public key from the private key
    SPHINXKey::SPHINXPubKey calculatePublicKey(const SPHINXKey::SPHINXPrivKey& privateKey) {
        // The length of the Kyber1024 public key
        constexpr size_t KYBER_PUBLIC_KEY_LENGTH = SPHINXKey::KYBER1024_PUBLIC_KEY_LENGTH;

        // The length of the X448 public key
        constexpr size_t X448_PUBLIC_KEY_LENGTH = SPHINXKey::CURVE448_PUBLIC_KEY_SIZE;

        // Calculate the SPHINX public key by extracting the Kyber1024 public key and X448 public key from the merged private key
        SPHINXKey::SPHINXPubKey publicKey(privateKey.begin() + KYBER_PUBLIC_KEY_LENGTH, privateKey.begin() + KYBER_PUBLIC_KEY_LENGTH + X448_PUBLIC_KEY_LENGTH);

        return publicKey;
    }

    // Function to generate the smart contract address based on the public key and contract name
    std::string generateAddress(const SPHINXKey::SPHINXPubKey& publicKey, const std::string& contractName) {
        // Assume the definition of SPHINXHash::SPHINX_256 function
        std::string hash = SPHINXHash::SPHINX_256(SPHINXPubKey);

        std::string contractIdentifier = contractName + "_" + hash;

        // Function to print the key pair information
        auto printKeyPair = [](const SPHINXHybridKey::HybridKeypair& hybridKeyPair, const std::string& address) {
            // Extract the public key from the merged key pair
            SPHINXKey::SPHINXPubKey publicKey = hybridKeyPair.merged_key.kyber_public_key;
            std::string mergedPublicKey(reinterpret_cast<const char*>(publicKey.data()), publicKey.size());

            // Print the merged public key and address
            std::cout << "Merged Public key: " << mergedPublicKey << std::endl;
            std::cout << "Address: " << address << std::endl;
        };

        // Call the original function from "hybrid_key.cpp"
        SPHINXHybridKey::HybridKeypair hybrid_keypair = SPHINXHybridKey::generate_hybrid_keypair();

        // Call the printKeyPair function to print the merged public key and address
        printKeyPair(hybrid_keypair, contractIdentifier);

        return contractIdentifier;
    }
} // namespace SPHINXKey
