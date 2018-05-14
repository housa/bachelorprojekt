//
// Created by housa on 5/14/18.
//

#ifndef PROJECT_SNARK_H
#define PROJECT_SNARK_H

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

namespace bp {

    template<typename ppT>
    class Fisk {
    public:
        //generator algorithm
        libsnark::r1cs_ppzksnark_keypair<ppT> generate(libsnark::r1cs_constraint_system<libff::Fr<ppT>> r1cs,
                                                         bool test_serialization);

        //prover algorithm
        libsnark::r1cs_ppzksnark_proof<ppT> prove(libsnark::r1cs_ppzksnark_proving_key<ppT> pk,
                                                  libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input,
                                                  libsnark::r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary_input,
                                                  bool test_serialization);

        //verifier algorithm
        bool verify(libsnark::r1cs_ppzksnark_verification_key<ppT> vk,
                    libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input,
                    libsnark::r1cs_ppzksnark_proof<ppT> proof);
    };
}

#include "snark.tpp"

#endif //PROJECT_SNARK_H
