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
#include "utils.h"

namespace bp {

    template<typename FieldT>
    class WebstrateSnark {
    private:
        std::shared_ptr<libsnark::protoboard<FieldT>> pb;
        std::shared_ptr<libsnark::pb_variable_array<FieldT>> primary_in;
        std::shared_ptr<libsnark::pb_variable_array<FieldT>> witness;
        std::shared_ptr<libsnark::pb_variable_array<FieldT>> lc_aux;
        std::vector<libsnark::packing_gadget<FieldT>> vector_of_packing_gadgets;
        std::vector<libsnark::sha256_two_to_one_hash_gadget<FieldT>> vector_of_hashing_gadgets;

        std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>> sha256;

    public:
        WebstrateSnark(const size_t tree_size) {
            // SHA blocks
            assert(tree_size % 512 == 0);

            pb = std::shared_ptr<libsnark::protoboard<FieldT>>(new libsnark::protoboard<FieldT>);

            primary_in = std::shared_ptr<libsnark::pb_variable_array<FieldT>>(new libsnark::pb_variable_array<FieldT>);
            witness = std::shared_ptr<libsnark::pb_variable_array<FieldT>>(new libsnark::pb_variable_array<FieldT>);

            lc_aux = std::shared_ptr<libsnark::pb_variable_array<FieldT>>(new libsnark::pb_variable_array<FieldT>);


            primary_in->allocate(*pb, 8, "in");
            witness->allocate(*pb, tree_size, "witness");

            lc_aux->allocate(*pb, 8, "lc_aux");

            // Digest first 512
            std::shared_ptr<libsnark::digest_variable<FieldT>> out(new libsnark::digest_variable<FieldT> (*pb, 256, "output"));

            libsnark::pb_variable_array<FieldT> witness_first512(witness->begin(), witness->begin() + 512);

            sha256 = std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>>(
                    new libsnark::sha256_compression_function_gadget<FieldT>(*pb,
                                                                             libsnark::SHA256_default_IV(*pb),
                                                                             witness_first512,
                                                                             *out,
                                                                             "sha"));

            // Digest old_digest + 256 new bits until no more
            S32 chunk_size = libsnark::SHA256_block_size / 2;

            for (S32 i = libsnark::SHA256_block_size; i < witness->size(); i += chunk_size) {
                libsnark::digest_variable<FieldT>* tmp_out = new libsnark::digest_variable<FieldT>(*pb, 256, "output");
                libsnark::pb_variable_array<FieldT> witness_next256(witness->begin() + i, witness->begin() + i + chunk_size);
                libsnark::digest_variable<FieldT> next256(*pb, chunk_size, witness_next256, 0, "256 bit chink digest");
                libsnark::sha256_two_to_one_hash_gadget<FieldT> hg(*pb, *out, next256, *tmp_out, "2to1 hash");

                out.reset(tmp_out);
                vector_of_hashing_gadgets.push_back(hg);
            }

            libsnark::pb_variable_array<FieldT> lc_arr(out->bits);

            for (int j = 0; j < 8; ++j) {
                libsnark::pb_linear_combination<FieldT> packedResult((*lc_aux)[j]);
                libsnark::pb_variable_array<FieldT> lc_aux_arr(lc_arr.rbegin() + j * 32, lc_arr.rbegin() + (j + 1) * 32);

                vector_of_packing_gadgets.push_back(libsnark::packing_gadget<FieldT>(*pb, lc_aux_arr, packedResult, "packing"));
            }
        }

        void set_num_of_inputs(const size_t num_inputs) {
            pb->set_input_sizes(num_inputs);
        }

        void generate_r1cs_constraints() {
            sha256->generate_r1cs_constraints();

            for (int k = 0; k < vector_of_hashing_gadgets.size(); ++k) {
                vector_of_hashing_gadgets[k].generate_r1cs_constraints(1);
            }

            for (int j = 0; j < vector_of_packing_gadgets.size(); ++j) {
                vector_of_packing_gadgets[j].generate_r1cs_constraints(1);

                pb->add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(1, (*lc_aux)[j], (*primary_in)[7 - j]),
                                        "eq constraint");
            }
        }

        libsnark::r1cs_auxiliary_input<FieldT> generate_r1cs_witness(libsnark::r1cs_primary_input<FieldT> input,
                                                                     libsnark::r1cs_auxiliary_input<FieldT> auxiliary_input) {
            for (int k = 0; k < 8; ++k) {
                pb->val((*primary_in)[k]) = input[k];
            }

            for (int i = 0; i < witness->size(); ++i) {
                pb->val((*witness)[i]) = auxiliary_input[i];
            }

            sha256->generate_r1cs_witness();

            for (int l = 0; l < vector_of_hashing_gadgets.size(); ++l) {
                vector_of_hashing_gadgets[l].generate_r1cs_witness();
            }

            printf("FiskeMaster[i]: h(aux)[i] = primary[i] \n");
            for (int j = 0; j < vector_of_packing_gadgets.size(); ++j) {
                vector_of_packing_gadgets[j].generate_r1cs_witness_from_bits();

                printf("FiskeMaster[%d]: %lx = %lx \n", j, pb->val((*lc_aux)[j]).as_ulong(), pb->val((*primary_in)[7 - j]).as_ulong());
            }

            return pb->auxiliary_input();
        }

        libsnark::r1cs_constraint_system<FieldT> get_constraint_system() {
            return pb->get_constraint_system();
        }
    };

}

#endif //PROJECT_SHA_TEST_H
