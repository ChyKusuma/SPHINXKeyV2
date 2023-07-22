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
// TThe provided code defines various functions related to generating and working with hybrid key pairs using cryptographic algorithms like Curve448, Kyber1024, and SPHINXhash hash functions.

// Constants and Type Aliases:
    // The code defines various constants related to key sizes (CURVE448_PRIVATE_KEY_SIZE, CURVE448_PUBLIC_KEY_SIZE, KYBER1024_PUBLIC_KEY_LENGTH) and HYBRID_KEYPAIR_LENGTH, which represents the size of the hybrid key pair as the sum of sizes of Curve448 public key, Kyber1024 public key, and twice the HMAC maximum message digest size (HMAC_MAX_MD_SIZE).
    // The code also defines two type aliases: SPHINXPubKey and SPHINXPrivKey, which represent the public and private keys in the SPHINXKey namespace.

// calculatePublicKey(const SPHINXKey::SPHINXPrivKey& privateKey):
    // This function takes a private key (privateKey) and calculates the corresponding SPHINX public key by extracting the Kyber1024 public key from the merged private key.

// sphinxKeyToString(const SPHINXKey::SPHINXKey& key):
    // This function converts a SPHINXKey to a string by concatenating its bytes.

// generateAddress(const SPHINXKey::SPHINXPubKey& publicKey, const std::string& contractName):
    // This function generates a smart contract address based on a given public key and a contract name.
    // It converts the public key to a string, hashes it using the SPHINX_256 hash function (not fully implemented), and then concatenates the contract name with the hash to form the contract identifier.

// generate_hybrid_keypair():
    // This function generates a hybrid key pair by combining keys from Curve448 and Kyber1024 algorithms.
    // It generates private and public keys for both algorithms and then merges them using the mergePrivateKeys and mergePublicKeys lambda functions.
    // The resulting hybrid key pair is returned as a structure of type SPHINXHybridKey::HybridKeypair.

// generate_and_perform_key_exchange():
    // This function generates and performs key exchange using the hybrid key pair.
    // It generates private and public keys for Curve448 and Kyber1024 algorithms.
    // The private keys are merged using the mergePrivateKeys lambda function, and the public keys are merged using the mergePublicKeys lambda function.
    // It then performs key exchange using X448 and Kyber1024 KEM (Key Encapsulation Mechanism).
    // After exchanging the keys, it encrypts and decrypts a sample message using Kyber1024 PKE (Public Key Encryption).
    // The original message, encrypted message, and decrypted message are printed.
    // Finally, the shared secret is returned as specified in the function signature.

// printKeyPair(const std::string& name, const SPHINXKey::SPHINXPrivKey& privateKey, const SPHINXKey::SPHINXPubKey& publicKey):
    // This function takes a name (for identification), a private key, and a public key as inputs.
    // It converts the private and public keys to strings and prints them.
    // It generates a contract address using the public key and a contract name.
    // The private key, public key, and contract address are returned as strings in a pair.

// Note: Some functions such as SPHINX_256, generateCurve448PrivateKey, generateCurve448PublicKey, generateKyberPrivateKey, generateKyberPublicKey, encapsulateHybridSharedSecret, and decapsulateHybridSharedSecret are to be defined in "Hash.hpp" and "Hybrid_Key.hpp". Their functionality is crucial for the correct operation of the generate_and_perform_key_exchange() function.

// The SPHINXKey namespace provides a set of utility functions to work with the SPHINX cryptographic scheme and interacts with other functions available in the SPHINXHybridKey namespace to generate a hybrid key pair and perform key exchange and encryption operations using the Kyber1024, X448, and PKE schemes.
////////////////////////////////////////////////////////////////////////////////////////////////////////


#include <string>
#include <vector>
#include <cstring>
#include <utility>
#include <iostream>
#include <algorithm>
#include <cstdint>

#include "Hybrid_key.hpp"
#include "Hash.hpp"
#include "Key.hpp"
#include "Consensus/Contract.hpp"


namespace SPHINXHybridKey {
    // Assume the definition of SPHINXHybridKey
    struct HybridKeypair {};
}

namespace SPHINXHash {
    // Assume the definition of SPHINX_256 function
    std::string SPHINX_256(const std::vector<unsigned char>& data) {
        // Dummy implementation for demonstration purposes
        return "hashed_" + std::string(data.begin(), data.end());
    }
}

namespace SPHINXKey {

    // Constants
    constexpr size_t CURVE448_PRIVATE_KEY_SIZE = 56;
    constexpr size_t CURVE448_PUBLIC_KEY_SIZE = 56;
    constexpr size_t KYBER1024_PUBLIC_KEY_LENGTH = 800;
    
    // Size of HYBRIDKEY
    constexpr size_t HYBRID_KEYPAIR_LENGTH = SPHINXHybridKey::CURVE448_PUBLIC_KEY_SIZE + SPHINXHybridKey::KYBER1024_PUBLIC_KEY_LENGTH + 2 * SPHINXHybridKey::HMAC_MAX_MD_SIZE;
    HYBRID_KEYPAIR_LENGTH = 56 (Curve448 public key size) + 800 (Kyber1024 public key length) + 2 * 64 (HMAC_MAX_MD_SIZE) = 976;

    // Define an alias for the merged public key as SPHINXPubKey
    using SPHINXPubKey = std::vector<unsigned char>;

    // Define an alias for the merged private key as SPHINXPrivKey
    using SPHINXPrivKey = std::vector<unsigned char>;

    // Function to calculate the SPHINX public key from the private key
    SPHINXKey::SPHINXPubKey calculatePublicKey(const SPHINXKey::SPHINXPrivKey& privateKey) {
        // The length of the Kyber1024 public key
        constexpr size_t KYBER_PUBLIC_KEY_LENGTH = SPHINXKey::KYBER1024_PUBLIC_KEY_LENGTH;

        // Calculate the SPHINX public key by extracting the Kyber1024 public key from the merged private key
        SPHINXKey::SPHINXPubKey sphinxPubKey(privateKey.begin() + CURVE448_PRIVATE_KEY_SIZE, privateKey.end());

        return sphinxPubKey;
    }

    // Function to convert SPHINXKey to string
    std::string sphinxKeyToString(const SPHINXKey::SPHINXKey& key) {
        return std::string(key.begin(), key.end());
    }

    // Function to generate the smart contract address based on the public key and contract name
    std::string generateAddress(const SPHINXKey::SPHINXPubKey& publicKey, const std::string& contractName) {
        // Assume the definition of SPHINXHash::SPHINX_256 function
        std::string pubKeyString = sphinxKeyToString(publicKey);
        std::string hash = SPHINXHash::SPHINX_256(pubKeyString);
        std::string contractIdentifier = contractName + "_" + hash;
        return contractIdentifier;
    }

    // Function to generate the hybrid key pair from "hybrid_key.cpp"
    SPHINXHybridKey::HybridKeypair generate_hybrid_keypair() {
        // Function to merge the private keys of Curve448 and Kyber1024
        auto mergePrivateKeys = [](const SPHINXKey::SPHINXPrivKey& curve448PrivateKey, const SPHINXKey::SPHINXPrivKey& kyberPrivateKey) {
            SPHINXKey::SPHINXPrivKey mergedPrivateKey;
            mergedPrivateKey.insert(mergedPrivateKey.end(), curve448PrivateKey.begin(), curve448PrivateKey.end());
            mergedPrivateKey.insert(mergedPrivateKey.end(), kyberPrivateKey.begin(), kyberPrivateKey.end());
            return SPHINXHash::SPHINX_256(mergedPrivateKey); // Hash the merged private key
        };

        // Function to merge the public keys of Curve448 and Kyber1024
        auto mergePublicKeys = [](const SPHINXKey::SPHINXPubKey& curve448PublicKey, const SPHINXKey::SPHINXPubKey& kyberPublicKey) {
            SPHINXKey::SPHINXPubKey mergedPublicKey;
            mergedPublicKey.insert(mergedPublicKey.end(), curve448PublicKey.begin(), curve448PublicKey.end());
            mergedPublicKey.insert(mergedPublicKey.end(), kyberPublicKey.begin(), kyberPublicKey.end());
            return SPHINXHash::SPHINX_256(mergedPublicKey); // Hash the merged public key
        };

        // Generate Curve448 key pair from hybrid_key.cpp
        SPHINXKey::SPHINXPrivKey curve448PrivateKey = generateCurve448PrivateKey();
        SPHINXKey::SPHINXPubKey curve448PublicKey = generateCurve448PublicKey();

        // Generate Kyber1024 key pair from hybrid_key.cpp
        SPHINXKey::SPHINXPrivKey kyberPrivateKey = generateKyberPrivateKey();
        SPHINXKey::SPHINXPubKey kyberPublicKey = generateKyberPublicKey();

        // Merge the private keys
        SPHINXKey::SPHINXPrivKey sphinxPrivKey = mergePrivateKeys(curve448PrivateKey, kyberPrivateKey);

        // Merge the public keys
        SPHINXKey::SPHINXPubKey sphinxPubKey = mergePublicKeys(curve448PublicKey, kyberPublicKey);

        // Create the hybrid key pair structure
        SPHINXHybridKey::HybridKeypair hybridKeyPair;
        hybridKeyPair.merged_key.sphinxPrivKey = sphinxPrivKey;
        hybridKeyPair.merged_key.sphinxPubKey = sphinxPubKey;

        return hybridKeyPair;
    }

    // Function to generate and perform key exchange hybrid method from "hybrid_key.cpp"
    SPHINXHybridKey::HybridKeypair generate_and_perform_key_exchange() {
        // Function to merge the private keys of Curve448 and Kyber1024
        auto mergePrivateKeys = [](const SPHINXKey::SPHINXPrivKey& curve448PrivateKey, const SPHINXKey::SPHINXPrivKey& kyberPrivateKey) {
            SPHINXKey::SPHINXPrivKey mergedPrivateKey;
            mergedPrivateKey.insert(mergedPrivateKey.end(), curve448PrivateKey.begin(), curve448PrivateKey.end());
            mergedPrivateKey.insert(mergedPrivateKey.end(), kyberPrivateKey.begin(), kyberPrivateKey.end());
            return SPHINXHash::SPHINX_256(mergedPrivateKey); // Hash the merged private key
        };

        // Function to merge the public keys of Curve448 and Kyber1024
        auto mergePublicKeys = [](const SPHINXKey::SPHINXPubKey& curve448PublicKey, const SPHINXKey::SPHINXPubKey& kyberPublicKey) {
            SPHINXKey::SPHINXPubKey mergedPublicKey;
            mergedPublicKey.insert(mergedPublicKey.end(), curve448PublicKey.begin(), curve448PublicKey.end());
            mergedPublicKey.insert(mergedPublicKey.end(), kyberPublicKey.begin(), kyberPublicKey.end());
            return SPHINXHash::SPHINX_256(mergedPublicKey); // Hash the merged public key
        };

        // Generate Curve448 key pair
        SPHINXKey::SPHINXPrivKey curve448PrivateKey = SPHINXHybridKey::generateCurve448PrivateKey();
        SPHINXKey::SPHINXPubKey curve448PublicKey = SPHINXHybridKey::generateCurve448PublicKey();

        // Generate Kyber1024 key pair
        SPHINXKey::SPHINXPrivKey kyberPrivateKey = SPHINXHybridKey::generateKyberPrivateKey();
        SPHINXKey::SPHINXPubKey kyberPublicKey = SPHINXHybridKey::generateKyberPublicKey();

        // Merge the private keys
        SPHINXKey::SPHINXPrivKey sphinxPrivKey = mergePrivateKeys(curve448PrivateKey, kyberPrivateKey);

        // Merge the public keys
        SPHINXKey::SPHINXPubKey sphinxPubKey = mergePublicKeys(curve448PublicKey, kyberPublicKey);

        // Create the hybrid key pair structure
        SPHINXHybridKey::HybridKeypair hybridKeyPair;
        hybridKeyPair.merged_key.sphinxPrivKey = sphinxPrivKey;
        hybridKeyPair.merged_key.sphinxPubKey = sphinxPubKey;

        // Perform the key exchange using X448 and Kyber1024 KEM
        std::vector<uint8_t> encapsulated_key;
        std::string shared_secret = SPHINXHybridKey::encapsulateHybridSharedSecret(hybridKeyPair, encapsulated_key);

        // Decapsulate the shared secret using Kyber1024 KEM
        std::string decapsulated_shared_secret = SPHINXHybridKey::decapsulateHybridSharedSecret(hybridKeyPair, encapsulated_key);

        // Check if the decapsulated shared secret matches the original shared secret
        if (decapsulated_shared_secret == shared_secret) {
            std::cout << "Decapsulation successful. Shared secrets match." << std::endl;
        } else {
            std::cout << "Decapsulation failed. Shared secrets do not match." << std::endl;
        }

        // Example message to be encrypted
        std::string message = "Hello, this is a secret message.";

        // Encrypt the message using Kyber1024 PKE with the public key
        std::string encrypted_message = SPHINXHybridKey::encryptMessage(message, hybridKeyPair.public_key_pke);

        // Decrypt the message using Kyber1024 PKE with the secret key
        std::string decrypted_message = SPHINXHybridKey::decryptMessage(encrypted_message, hybridKeyPair.secret_key_pke);

        // Print the original message, encrypted message, and decrypted message
        std::cout << "Original Message: " << message << std::endl;
        std::cout << "Encrypted Message: " << encrypted_message << std::endl;
        std::cout << "Decrypted Message: " << decrypted_message << std::endl;

        // Return the shared secret as specified in the function signature
        return shared_secret;
    }

    // Function to print the generated keys and return them as strings
    std::pair<std::string, std::string> printKeyPair(const std::string& name, const SPHINXKey::SPHINXPrivKey& privateKey, const SPHINXKey::SPHINXPubKey& publicKey) {
        // Convert private key to string
        std::string privKeyString = sphinxKeyToString(privateKey);
        // Convert public key to string
        std::string pubKeyString = sphinxKeyToString(publicKey);

        // Print the private and public keys
        std::cout << name << " private key: " << privKeyString << std::endl;
        std::cout << name << " public key: " << pubKeyString << std::endl;

        // Generate and print the contract address
        std::string contractName = "MyContract";
        std::string contractAddress = generateAddress(publicKey, contractName);
        std::cout << "Contract Address: " << contractAddress << std::endl;

        // Return the keys and contract address as strings
        return std::make_pair(privKeyString, pubKeyString);
    }
} // namespace SPHINXKey


// Usage
int main() {
    // Generate the hybrid key pair
    SPHINXHybridKey::HybridKeypair hybridKeyPair = SPHINXKey::generate_hybrid_keypair();

    // Print the hybrid key pair
    std::cout << "Hybrid Key Pair:" << std::endl;
    std::cout << "Merged Private Key: ";
    for (const auto& byte : hybridKeyPair.merged_key.sphinxPrivKey) {
        std::cout << std::hex << static_cast<int>(byte);
    }
    std::cout << std::endl;

    std::cout << "Merged Public Key: ";
    for (const auto& byte : hybridKeyPair.merged_key.sphinxPubKey) {
        std::cout << std::hex << static_cast<int>(byte);
    }
    std::cout << std::endl;

    // Generate and perform key exchange
    SPHINXHybridKey::HybridKeypair exchangedKeys = SPHINXKey::generate_and_perform_key_exchange();

    // Print the shared secret (Example: For demonstration purposes)
    std::cout << "Shared Secret: ";
    for (const auto& byte : exchangedKeys.shared_secret) {
        std::cout << std::hex << static_cast<int>(byte);
    }
    std::cout << std::endl;

    // Call the printKeyPair function to print and get the keys and contract address as strings
    std::pair<std::string, std::string> keys = SPHINXKey::printKeyPair("ExampleKeyPair", exchangedKeys.merged_key.sphinxPrivKey, exchangedKeys.merged_key.sphinxPubKey);

    // Access the keys and contract address as strings
    std::string private_key_str = keys.first;
    std::string public_key_str = keys.second;

    // Example usage: print the keys and contract address
    std::cout << "Private Key as String: " << private_key_str << std::endl;
    std::cout << "Public Key as String: " << public_key_str << std::endl;

    return 0;
}
