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
    libsnark::r1cs_constraint_system<FieldT> gen_webstrate_constraint_system(const size_t tree_size) {

        /* construct variables: */
        libsnark::protoboard<FieldT> pb;
        libsnark::pb_variable_array<FieldT> aux_in;
        libsnark::pb_variable<FieldT> primary_in1;
        libsnark::pb_variable<FieldT> primary_in2;
        libsnark::pb_variable<FieldT> primary_in3;
        libsnark::pb_variable<FieldT> primary_in4;
        libsnark::pb_variable<FieldT> less_eq1;
        libsnark::pb_variable<FieldT> less_eq2;
        libsnark::pb_variable<FieldT> less_eq3;
        libsnark::pb_variable<FieldT> less_eq4;
        libsnark::pb_variable<FieldT> less1;
        libsnark::pb_variable<FieldT> less2;
        libsnark::pb_variable<FieldT> less3;
        libsnark::pb_variable<FieldT> less4;
        libsnark::pb_variable<FieldT> lc_aux1;
        libsnark::pb_variable<FieldT> lc_aux2;
        libsnark::pb_variable<FieldT> lc_aux3;
        libsnark::pb_variable<FieldT> lc_aux4;
        libsnark::pb_linear_combination<FieldT> packed_result1(lc_aux1);
        libsnark::pb_linear_combination<FieldT> packed_result2(lc_aux2);
        libsnark::pb_linear_combination<FieldT> packed_result3(lc_aux3);
        libsnark::pb_linear_combination<FieldT> packed_result4(lc_aux4);

        primary_in1.allocate(pb, "h(T)1");
        primary_in2.allocate(pb, "h(T)2");
        primary_in3.allocate(pb, "h(T)3");
        primary_in4.allocate(pb, "h(T)4");
        aux_in.allocate(pb, tree_size, "T");
        lc_aux1.allocate(pb, "lc_aux");
        lc_aux2.allocate(pb, "lc_aux");
        lc_aux3.allocate(pb, "lc_aux");
        lc_aux4.allocate(pb, "lc_aux");
        less_eq1.allocate(pb, "leq1");
        less_eq2.allocate(pb, "leq2");
        less_eq3.allocate(pb, "leq3");
        less_eq4.allocate(pb, "leq4");
        less1.allocate(pb, "less1");
        less2.allocate(pb, "less2");
        less3.allocate(pb, "less3");
        less4.allocate(pb, "less4");
        libsnark::digest_variable<FieldT> out(pb, 256, "output");

        //hash part
        libsnark::sha256_compression_function_gadget<FieldT> sha256(pb,
                                                                    libsnark::SHA256_default_IV<FieldT>(pb),
                                                                    aux_in,
                                                                    out,
                                                                    "sha");
        sha256.generate_r1cs_constraints();
        sha256.generate_r1cs_witness();

        //comparison part

        //create linear combination from digest
        int i = 0;
        libsnark::pb_linear_combination_array<FieldT> lc_arr(out.bits);
        libsnark::pb_linear_combination_array<FieldT> lc_arr1(lc_arr.begin() + (i*64), lc_arr.begin() + (i+1) * 64);
        i++;
        libsnark::pb_linear_combination_array<FieldT> lc_arr2(lc_arr.begin() + (i*64), lc_arr.begin() + (i+1) * 64);
        i++;
        libsnark::pb_linear_combination_array<FieldT> lc_arr3(lc_arr.begin() + (i*64), lc_arr.begin() + (i+1) * 64);
        i++;
        libsnark::pb_linear_combination_array<FieldT> lc_arr4(lc_arr.begin() + (i*64), lc_arr.begin() + (i+1) * 64);

        //pack linear combination of digest
        libsnark::packing_gadget<FieldT> pg1(pb, lc_arr1, packed_result1, "packing");
        libsnark::packing_gadget<FieldT> pg2(pb, lc_arr2, packed_result2, "packing");
        libsnark::packing_gadget<FieldT> pg3(pb, lc_arr3, packed_result3, "packing");
        libsnark::packing_gadget<FieldT> pg4(pb, lc_arr4, packed_result4, "packing");

        pg1.generate_r1cs_constraints(1);
        pg1.generate_r1cs_witness_from_packed();
        pg2.generate_r1cs_constraints(1);
        pg2.generate_r1cs_witness_from_packed();
        pg3.generate_r1cs_constraints(1);
        pg3.generate_r1cs_witness_from_packed();
        pg4.generate_r1cs_constraints(1);
        pg4.generate_r1cs_witness_from_packed();

        //compare
        libsnark::comparison_gadget<FieldT> cmp1(pb, 64, primary_in1, packed_result1, less1, less_eq1, "compare");
        libsnark::comparison_gadget<FieldT> cmp2(pb, 64, primary_in2, packed_result2, less2, less_eq2, "compare");
        libsnark::comparison_gadget<FieldT> cmp3(pb, 64, primary_in3, packed_result3, less3, less_eq3, "compare");
        libsnark::comparison_gadget<FieldT> cmp4(pb, 64, primary_in4, packed_result4, less4, less_eq4, "compare");

        cmp1.generate_r1cs_constraints();
        cmp1.generate_r1cs_witness();
        cmp2.generate_r1cs_constraints();
        cmp2.generate_r1cs_witness();
        cmp3.generate_r1cs_constraints();
        cmp3.generate_r1cs_witness();
        cmp4.generate_r1cs_constraints();
        cmp4.generate_r1cs_witness();

        //check comparison result
        pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(less_eq1, 1-less1, FieldT::one()));
        pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(less_eq2, 1-less2, FieldT::one()));
        pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(less_eq3, 1-less3, FieldT::one()));
        pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(less_eq4, 1-less4, FieldT::one()));

        //return constraint system
        return pb.get_constraint_system();
    }

    template<typename FieldT>
    libsnark::r1cs_constraint_system<FieldT> gen_webstrate_constraint_system_minimal(const size_t tree_size) {

        /* construct variables: */
        libsnark::protoboard<FieldT> pb;
        libsnark::pb_variable<FieldT> primary_in;
        libsnark::pb_variable<FieldT> aux_in;
        libsnark::pb_variable<FieldT> aux_in2;

        primary_in.allocate(pb, "in");
        aux_in.allocate(pb, "aux in");
        aux_in2.allocate(pb, "aux in2");


        pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(aux_in2, aux_in, primary_in));

        //return constraint system
        return pb.get_constraint_system();
    }

}

#endif //PROJECT_SHA_TEST_H
