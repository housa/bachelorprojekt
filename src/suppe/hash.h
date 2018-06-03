//
// Created by housa on 6/3/18.
//

#ifndef PROJECT_HASH_H
#define PROJECT_HASH_H

#include <vector>
#include <depends/libff/libff/common/utils.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include "utils.h"
#include <algorithm>    // std::max

namespace bp {

    template<typename FieldT>
    void sha(std::vector<int>& input, std::vector<int>& dest) {

        // Convert input from vector<int>
        libff::bit_vector bv_in;
        transfer_vector_items(input, bv_in);

        // Zero-padding
        while (bv_in.size() % libsnark::SHA256_block_size != 0) {
            bv_in.push_back(0);
        }

        // Initialize hash with first block
        libff::bit_vector bv_tmp(bv_in.begin(), bv_in.begin() + min(libsnark::SHA256_block_size, bv_in.size()));
        libff::bit_vector bv_out = libsnark::sha256_two_to_one_hash_gadget<FieldT>::get_hash(bv_tmp);

        // Process rest of the hash in half-chunks so we can hash a vector is half previous output and half input.
        int chunk_size = libsnark::SHA256_block_size / 2;
        for (int i = libsnark::SHA256_block_size; i < bv_in.size(); i += chunk_size / 2) {
            bv_tmp.clear();
            bv_tmp.insert(bv_tmp.end(), bv_out.begin(), bv_out.end());
            bv_tmp.insert(bv_tmp.end(), bv_in.begin() + i, bv_in.begin() + i + chunk_size);
            bv_out = libsnark::sha256_two_to_one_hash_gadget<FieldT>::get_hash(bv_tmp);
        }

        // Convert output to int-vector
        transfer_vector_items(bv_out, dest);
    }
}

#endif //PROJECT_HASH_H
