//
// Created by housa on 5/14/18.
//
// Copy of libsnark test implementation, but split into gen, prove, verify
//

#include "snark.h"

namespace bp {

    template<typename ppT>
    libsnark::r1cs_ppzksnark_keypair<ppT> Fisk<ppT>::generate(libsnark::r1cs_constraint_system<libff::Fr<ppT>> r1cs,
                                                                bool test_serialization) {
        libff::enter_block("Call to run_r1cs_ppzksnark");

        libff::print_header("R1CS ppzkSNARK Generator");
        libsnark::r1cs_ppzksnark_keypair<ppT> keypair = libsnark::r1cs_ppzksnark_generator<ppT>(r1cs);
        printf("\n");
        libff::print_indent();
        libff::print_mem("after generator");

        //libff::print_header("Preprocess verification key");
        //libsnark::r1cs_ppzksnark_processed_verification_key<ppT> pvk = r1cs_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

        if (test_serialization) {
            libff::enter_block("Test serialization of keys");
            keypair.pk = libff::reserialize<libsnark::r1cs_ppzksnark_proving_key<ppT> >(keypair.pk);
            keypair.vk = libff::reserialize<libsnark::r1cs_ppzksnark_verification_key<ppT> >(keypair.vk);
            libff::leave_block("Test serialization of keys");
        }
        return keypair;
    }

    template<typename ppT>
    libsnark::r1cs_ppzksnark_proof<ppT> Fisk<ppT>::prove(libsnark::r1cs_ppzksnark_proving_key<ppT> pk,
                                                         libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input,
                                                         libsnark::r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary_input,
                                                         bool test_serialization) {
        libff::print_header("R1CS ppzkSNARK Prover");
        libsnark::r1cs_ppzksnark_proof<ppT> proof = libsnark::r1cs_ppzksnark_prover<ppT>(pk, primary_input,
                                                                                         auxiliary_input);
        printf("\n");
        libff::print_indent();
        libff::print_mem("after prover");

        if (test_serialization) {
            libff::enter_block("Test serialization of proof");
            proof = libff::reserialize<libsnark::r1cs_ppzksnark_proof<ppT> >(proof);
            libff::leave_block("Test serialization of proof");
        }
        return proof;
    }

    template<typename ppT>
    bool Fisk<ppT>::verify(libsnark::r1cs_ppzksnark_verification_key<ppT> vk,
                           libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input,
                           libsnark::r1cs_ppzksnark_proof<ppT> proof) {
        libff::print_header("R1CS ppzkSNARK Verifier");
        const bool ans = libsnark::r1cs_ppzksnark_verifier_strong_IC<ppT>(vk, primary_input, proof);
        printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
        printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

        libff::leave_block("Call to run_r1cs_ppzksnark");

        return ans;
    }

}