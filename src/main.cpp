#include <cassert>
#include <cstdio>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>

//files included to run libsnark example
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include "suppe/snark.h"
#include "suppe/sha_test.h"
#include "suppe/picosha2.h"

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

template<typename FieldT>
std::vector<FieldT> generate_input(const long int *vals, size_t cnt, size_t max)
{
    r1cs_variable_assignment<FieldT> full_variable_assignment;

    for (int j = 0; j < cnt; ++j) {
        full_variable_assignment.push_back(FieldT(vals[j]));
    }
    for (int k = 0; k < max - cnt; ++k) {
        full_variable_assignment.push_back(FieldT::zero());
    }

    return std::vector<FieldT>(full_variable_assignment.begin(), full_variable_assignment.begin() + max);
}

long int eight_ints_to_long_int(long int i0, long int i1, long int i2, long int i3, long int i4, long int i5, long int i6, long int i7) {

    return (i0 << 56) | (i1 << 48) | (i2 << 40) | (i3 << 32) | (i4 << 24) | (i5 << 16) | (i6 << 8) | i7;
}

template<typename ppT>
void test_r1cs_websnark(size_t input_size)
{

    typedef default_r1cs_ppzksnark_pp detype;
    typedef libff::Fr<detype> FieldT;

    //R1CS part
    libsnark::r1cs_constraint_system<FieldT> cs = bp::gen_webstrate_constraint_system<FieldT>(input_size);

    cs.primary_input_size = 4;
    cs.auxiliary_input_size -= cs.primary_input_size;

    //zksnark part
    bp::Fisk<ppT> fisk;
    //generate
    r1cs_ppzksnark_keypair<ppT> keypair = fisk.generate(cs, true);

    //create test input
    const long int input[] = {'1', '2'};
    libsnark::r1cs_auxiliary_input<FieldT> auxiliary_input = generate_input<FieldT>(input, 2, cs.auxiliary_input_size);

    std::string src_str = "12";

    std::vector<long int> hash(picosha2::k_digest_size);
    picosha2::hash256(src_str.begin(), src_str.end(), hash.begin(), hash.end());

    std::string hex_str = picosha2::bytes_to_hex_string(hash.begin(), hash.end());

    libsnark::r1cs_primary_input<FieldT> primary_input = generate_input<FieldT>(&hash[0], 4, 4);
    std::cout << hex_str;

    //prove
    libsnark::r1cs_ppzksnark_proof<ppT> proof = fisk.prove(keypair.pk, primary_input, auxiliary_input, true);
}

template<typename ppT>
void test_r1cs_minimal(size_t input_size)
{

    typedef default_r1cs_ppzksnark_pp detype;
    typedef libff::Fr<detype> FieldT;

    //R1CS part
    libsnark::r1cs_constraint_system<FieldT> cs = bp::gen_webstrate_constraint_system_minimal<FieldT>(input_size);

    cs.primary_input_size = 1;
    cs.auxiliary_input_size -= cs.primary_input_size;

    //zksnark part
    bp::Fisk<ppT> fisk;
    //generate
    r1cs_ppzksnark_keypair<ppT> keypair = fisk.generate(cs, true);

    //create test input

    const long int input[] = {42};
    libsnark::r1cs_primary_input<FieldT> primary_input = generate_input<FieldT>(input, 1, 1);

    const long int aux_input[] = {2, 21};
    libsnark::r1cs_auxiliary_input<FieldT> auxiliary_input = generate_input<FieldT>(aux_input, 2, cs.auxiliary_input_size);

    //prove
    libsnark::r1cs_ppzksnark_proof<ppT> proof = fisk.prove(keypair.pk, primary_input, auxiliary_input, true);

    //verify
    bool ans = fisk.verify(keypair.vk, primary_input, proof);
    assert(ans);

}

int main(int argc, const char * argv[])
{
    default_r1cs_ppzksnark_pp::init_public_params();
    libff::start_profiling();

    //test_r1cs_ppzksnark<default_r1cs_ppzksnark_pp>(1000, 100);

    //test_r1cs_websnark<default_r1cs_ppzksnark_pp>(1000);

    test_r1cs_minimal<default_r1cs_ppzksnark_pp>(1000);
}

/*
 *
    default_r1cs_ppzksnark_pp::init_public_params();
    libff::start_profiling();

    typedef default_r1cs_ppzksnark_pp detype;

    r1cs_example<libff::Fr<detype>> example = gen_sha256_example<libff::Fr<detype>>(1000);

    const bool bit = run_r1cs_ppzksnark<detype>(example, true);
 */