#include <cassert>
#include <cstdio>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>

//files included to run libsnark example
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include "suppe/snark.h"

using namespace libsnark;

//original test code taken from libsnark to be altered to fit use case
//TODO step 1: use own R1CS instead of example
template<typename ppT>
void test_r1cs_ppzksnark(size_t num_constraints,
                         size_t input_size)
{
    libff::print_header("(enter) Run R1CS ppzkSNARK");

    const bool test_serialization = true;

    //R1CS part
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);

    //zksnark part
    bp::Fisk<ppT> fisk;
    //generate
    r1cs_ppzksnark_keypair<ppT> keypair = fisk.generate(example.constraint_system, test_serialization);
    //prove
    libsnark::r1cs_ppzksnark_proof<ppT> proof = fisk.prove(keypair.pk, example.primary_input, example.auxiliary_input, test_serialization);
    //verify
    bool ans = fisk.verify(keypair.vk, example.primary_input, proof);
    assert(ans);

    libff::print_header("(leave) Run R1CS ppzkSNARK");
}

int main(int argc, const char * argv[])
{
    default_r1cs_ppzksnark_pp::init_public_params();
    libff::start_profiling();

    test_r1cs_ppzksnark<default_r1cs_ppzksnark_pp>(1000, 100);
}

/*
 *
    default_r1cs_ppzksnark_pp::init_public_params();
    libff::start_profiling();

    typedef default_r1cs_ppzksnark_pp detype;

    r1cs_example<libff::Fr<detype>> example = gen_sha256_example<libff::Fr<detype>>(1000);

    const bool bit = run_r1cs_ppzksnark<detype>(example, true);
 */