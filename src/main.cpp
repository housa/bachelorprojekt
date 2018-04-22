#include <cassert>
#include <cstdio>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>

//files included to run libsnark example
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>

using namespace libsnark;

//original test code taken from libsnark to be altered to fit use case
//TODO step 1: use own R1CS instead of example
template<typename ppT>
void test_r1cs_ppzksnark(size_t num_constraints,
                         size_t input_size)
{
    libff::print_header("(enter) Run R1CS ppzkSNARK");

    //R1CS part
    const bool test_serialization = true;
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);

    //zksnark part
    const bool bit = run_r1cs_ppzksnark<ppT>(example, test_serialization);
    assert(bit);

    libff::print_header("(leave) Run R1CS ppzkSNARK");
}

int main(int argc, const char * argv[])
{
    default_r1cs_ppzksnark_pp::init_public_params();
    libff::start_profiling();

    //TODO should in time be split  out so main calls 3 methods generate, proof, and verify
    test_r1cs_ppzksnark<default_r1cs_ppzksnark_pp>(1000, 100);
}