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

#include <string>
#include <vector>
#include <cstring>
#include <utility>
#include <iostream>

#include "Hybrid_key.hpp"
#include "Hash.hpp"


namespace SPHINXKey {

    // Function to generate the hybrid keypair
    HybridKeypair generate_hybrid_keypair();

    // Function to generate the Curve448 key pair
    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> generate_curve448_key_pair();

    // Function to generate the Kyber1024 key pair
    kyber1024_kem::PrivateKey generate_kyber1024_key_pair();

    // Function to merge the Curve448 and Kyber1024 key pairs
    HybridKeypair merge_key_pair(const std::pair<std::vector<unsigned char>, std::vector<unsigned char>>& curve448_key,
                                const kyber1024_kem::PrivateKey& kyber_key);

    // Function to perform the Curve448 key exchange
    void performCurve448KeyExchange(unsigned char shared_key[56], const unsigned char private_key[56], const unsigned char public_key[56]);

    // Function to perform the hybrid key exchange combining Curve448 and Kyber1024
    void performHybridKeyExchange(unsigned char shared_key[32], const std::pair<std::vector<unsigned char>, std::vector<unsigned char>>& curve448_key,
                                 const kyber1024_kem::PrivateKey& kyber_key);

    // Function to generate the hybrid keypair and perform the key exchange
    HybridKeypair generate_and_perform_key_exchange();

    // Function to generate the smart contract address based on the public key and contract name
    std::string generateAddress(const std::string& publicKey, const std::string& contractName);

    // Function to calculate the public key from the private key
    std::string calculatePublicKey(const std::string& privateKey);

    // Function to print the key pair information
    void printKeyPair(const SPHINXHybridKey::HybridKeypair& hybridKeyPair);

} // namespace SPHINXKey

#endif // SPHINX_KEY_HPP
