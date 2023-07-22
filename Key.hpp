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


#ifndef SPHINX_KEY_HPP
#define SPHINX_KEY_HPP

#pragma once

#include <string>
#include <vector>
#include <cstring>
#include <utility>
#include <iostream>
#include <algorithm>
#include <cstdint>

namespace SPHINXHybridKey {
    // Assume the definition of SPHINXHybridKey
    struct HybridKeypair {};
}

namespace SPHINXHash {
    // Assume the definition of SPHINX_256 function
    std::string SPHINX_256(const std::vector<unsigned char>& data);
}

namespace SPHINXKey {
    // Constants
    constexpr size_t CURVE448_PRIVATE_KEY_SIZE = 56;
    constexpr size_t CURVE448_PUBLIC_KEY_SIZE = 56;
    constexpr size_t KYBER1024_PUBLIC_KEY_LENGTH = 800;

    // Size of HYBRIDKEY
    constexpr size_t HYBRID_KEYPAIR_LENGTH = CURVE448_PUBLIC_KEY_SIZE + KYBER1024_PUBLIC_KEY_LENGTH + 2 * 64 (HMAC_MAX_MD_SIZE) = 976;
    // Assuming HMAC_MAX_MD_SIZE is defined elsewhere

    // Define an alias for the merged public key as SPHINXPubKey
    using SPHINXPubKey = std::vector<unsigned char>;

    // Define an alias for the merged private key as SPHINXPrivKey
    using SPHINXPrivKey = std::vector<unsigned char>;

    // Function to calculate the SPHINX public key from the private key
    SPHINXKey::SPHINXPubKey calculatePublicKey(const SPHINXKey::SPHINXPrivKey& privateKey);

    // Function to convert SPHINXKey to string
    std::string sphinxKeyToString(const SPHINXKey::SPHINXKey& key);

    // Function to generate the smart contract address based on the public key and contract name
    std::string generateAddress(const SPHINXKey::SPHINXPubKey& publicKey, const std::string& contractName);

    // Function to generate the hybrid key pair from "hybrid_key.cpp"
    SPHINXHybridKey::HybridKeypair generate_hybrid_keypair();

    // Function to generate and perform key exchange hybrid method from "hybrid_key.cpp"
    SPHINXHybridKey::HybridKeypair generate_and_perform_key_exchange();

    // Function to print the generated keys and return them as strings
    std::pair<std::string, std::string> printKeyPair(const std::string& name, const SPHINXKey::SPHINXPrivKey& privateKey, const SPHINXKey::SPHINXPubKey& publicKey);
}

#endif // SPHINX_KEY_HPP
