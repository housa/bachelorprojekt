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
    class WebstrateSnark {
    private:
        std::shared_ptr<libsnark::protoboard<FieldT>> pb;
        std::shared_ptr<libsnark::pb_variable_array<FieldT>> primary_in;
        std::shared_ptr<libsnark::pb_variable_array<FieldT>> witness;
        std::shared_ptr<libsnark::digest_variable<FieldT>> out;
        std::shared_ptr<libsnark::pb_variable<FieldT>> lc_aux1;
        std::shared_ptr<libsnark::packing_gadget<FieldT>> pg1;

        std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>> sha256;

    public:
        WebstrateSnark(const size_t tree_size) {
            // SHA blocks
            assert(tree_size % 512 == 0);

            pb = std::shared_ptr<libsnark::protoboard<FieldT>>(new libsnark::protoboard<FieldT>);

            primary_in = std::shared_ptr<libsnark::pb_variable_array<FieldT>>(new libsnark::pb_variable_array<FieldT>);
            witness = std::shared_ptr<libsnark::pb_variable_array<FieldT>>(new libsnark::pb_variable_array<FieldT>);

            lc_aux1 = std::shared_ptr<libsnark::pb_variable<FieldT>>(new libsnark::pb_variable<FieldT>);


            primary_in->allocate(*pb, 8, "in");
            witness->allocate(*pb, tree_size, "witness");

            lc_aux1->allocate(*pb, "lc_aux1");

            libsnark::pb_linear_combination<FieldT> packed_result1(*lc_aux1);

            out = std::shared_ptr<libsnark::digest_variable<FieldT>>(
                    new libsnark::digest_variable<FieldT>(*pb, 256, "output"));


            sha256 = std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>>(
                    new libsnark::sha256_compression_function_gadget<FieldT>(*pb,
                                                                             libsnark::SHA256_default_IV(*pb),
                                                                             *witness,
                                                                             *out,
                                                                             "sha"));

            libsnark::pb_variable_array<FieldT> lc_arr(out->bits);
            int i = 0;
            libsnark::pb_variable_array<FieldT> lc_arr1(lc_arr.rbegin() + i * 32, lc_arr.rbegin() + (i + 1) * 32);

            pg1 = std::shared_ptr<libsnark::packing_gadget<FieldT>>(new libsnark::packing_gadget<FieldT>(*pb, lc_arr1, packed_result1, "packing1"));
        }

        void set_num_of_inputs(const size_t num_inputs) {
            pb->set_input_sizes(num_inputs);
        }

        void generate_r1cs_constraints() {
            sha256->generate_r1cs_constraints();

            pg1->generate_r1cs_constraints(1);

            pb->add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(1, *lc_aux1, (*primary_in)[7]),
                                    "eq constraint");
        }

        libsnark::r1cs_auxiliary_input<FieldT> generate_r1cs_witness(libsnark::r1cs_primary_input<FieldT> input,
                                                                     libsnark::r1cs_auxiliary_input<FieldT> auxiliary_input) {
            pb->val((*primary_in)[0]) = input[0];

            for (int i = 0; i < witness->size(); ++i) {
                pb->val((*witness)[i]) = auxiliary_input[i];
            }

            sha256->generate_r1cs_witness();

            pg1->generate_r1cs_witness_from_bits();

            printf("FiskeMaster: %lx \n", pb->val(*lc_aux1).as_ulong());

            return pb->auxiliary_input();
        }

        libsnark::r1cs_constraint_system<FieldT> get_constraint_system() {
            return pb->get_constraint_system();
        }
    };

}

#endif //PROJECT_SHA_TEST_H
