//
// Created by housa on 5/14/18.
//

#ifndef PROJECT_SHA_TEST_H
#define PROJECT_SHA_TEST_H

#include <cstdio>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

namespace bp {

    template<typename FieldT>
    libsnark::r1cs_example<FieldT> gen_sha256_example(const size_t num_inputs) {
        const size_t new_num_inputs = num_inputs - 1;

/* construct dummy example: inner products of two vectors */
        libsnark::protoboard<FieldT> pb;
        libsnark::pb_variable_array<FieldT> in;
        libsnark::digest_variable<FieldT> out(pb, 256, "output");

        in.allocate(pb, new_num_inputs, "in");

        libsnark::sha256_compression_function_gadget<FieldT> sha256(pb, libsnark::SHA256_default_IV<FieldT>(pb), in,
                                                                    out,
                                                                    "sha");
        sha256.generate_r1cs_constraints();

/* fill in random example */
        for (size_t i = 0; i < new_num_inputs; ++i) {
            pb.val(in[i]) = FieldT::random_element();
        }

//sha256.generate_r1cs_witness();
//out.generate_r1cs_witness();
        return libsnark::r1cs_example<FieldT>(pb.get_constraint_system(), pb.primary_input(), pb.auxiliary_input());
    }
}

#endif //PROJECT_SHA_TEST_H
