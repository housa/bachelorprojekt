//
// Created by housa on 6/3/18.
//

#ifndef PROJECT_UTILS_H
#define PROJECT_UTILS_H


#include <cstddef>
#include <vector>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

#define BIT(N, x) (((x) >> (N)) & 1)
// Types
#define U32 unsigned int
#define S32 int


void add_int_to_bit_vector(U32 val, libff::bit_vector& dest) {
    for (S32 k = 31; k >= 0 ; k--) {
        dest.push_back(BIT(k, val));
    }
}

void transfer_vector_items(libff::bit_vector& src, std::vector<U32>& dest) {
    for (S32 i = 0; i < src.size(); i += 32) {
        U32 r = 0;
        for (S32 j = 0; j < 32; ++j) {
            r |= (src[i+j] ? 1 : 0) << (31 - j);
        }
        dest.push_back(r);
    }
}

void transfer_vector_items(std::vector<U32>& src, libff::bit_vector& dest) {
    // Add all inputs to bit_vector
    for (S32 i : src) {
        add_int_to_bit_vector(i, dest);
    }
}


template<typename FieldT>
std::vector<FieldT> generate_bit_vec_input(std::vector<U32> vals, size_t max)
{
    libsnark::r1cs_variable_assignment<FieldT> full_variable_assignment;

    U32 input_size = 32*vals.size();

    for (U32 val : vals) {
        libff::bit_vector bv;
        add_int_to_bit_vector(val, bv);
        for (S32 i = 0; i < 32; ++i) {
            full_variable_assignment.push_back(FieldT(bv[i]));
        }
    }
    for (S32 k = 0; k < max - input_size; ++k) {
        full_variable_assignment.push_back(FieldT(0));
    }

    return std::vector<FieldT>(full_variable_assignment.begin(), full_variable_assignment.begin() + max);
}

template<typename FieldT>
std::vector<FieldT> generate_input(std::vector<U32> vals, size_t max)
{
    libsnark::r1cs_variable_assignment<FieldT> full_variable_assignment;

    for (U32 &val : vals) {
        full_variable_assignment.push_back(FieldT(val));
    }
    for (S32 k = 0; k < max - vals.size(); ++k) {
        if (k == 0) {
            full_variable_assignment.push_back(FieldT(0x80000000));
        } else {
            full_variable_assignment.push_back(FieldT(0));
        }
    }

    return std::vector<FieldT>(full_variable_assignment.begin(), full_variable_assignment.begin() + max);
}

int max(int a, int b) {
    return a > b ? a : b;
}

int min(int a, int b) {
    return a < b ? a : b;
}

#endif //PROJECT_UTILS_H
