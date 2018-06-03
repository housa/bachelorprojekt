#define DEBUG true

#include <cassert>
#include <cstdio>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>

//files included to run libsnark example
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include "suppe/snark.h"
#include "suppe/webstrate_cs.h"
#include "suppe/picosha2.h"

#define BIT(N, x) (((x) >> (N)) & 1)

using namespace libsnark;

template<typename FieldT>
std::vector<FieldT> generate_input(const long *vals, size_t cnt, size_t max)
{
    r1cs_variable_assignment<FieldT> full_variable_assignment;

    for (int j = 0; j < cnt; ++j) {
        full_variable_assignment.push_back(FieldT(vals[j]));
    }
    for (int k = 0; k < max - cnt; ++k) {
        if (k == 0) {
            full_variable_assignment.push_back(FieldT(0x80000000));
        } else {
            full_variable_assignment.push_back(FieldT(0));
        }
    }

    return std::vector<FieldT>(full_variable_assignment.begin(), full_variable_assignment.begin() + max);
}

template<typename FieldT>
std::vector<FieldT> generate_bit_vec_input(const long int *vals, size_t cnt, size_t max)
{
    r1cs_variable_assignment<FieldT> full_variable_assignment;

    int input_size = 32*cnt;

    for (int j = 0; j < cnt; ++j) {
        for (int k = 31; k >= 0 ; --k) {
            full_variable_assignment.push_back(FieldT(BIT(k, vals[j])));
        }
    }
    for (int k = 0; k < max - input_size; ++k) {
        full_variable_assignment.push_back(FieldT(0));
    }

    return std::vector<FieldT>(full_variable_assignment.begin(), full_variable_assignment.begin() + max);
}


template<typename ppT>
void test_r1cs_minimal(size_t input_size)
{

    typedef default_r1cs_ppzksnark_pp detype;
    typedef libff::Fr<detype> FieldT;

    //R1CS part
    bp::WebstrateSnark<FieldT> webstrateSnark(input_size);
    webstrateSnark.generate_r1cs_constraints();

    webstrateSnark.set_num_of_inputs(1);

    libsnark::r1cs_constraint_system<FieldT> cs = webstrateSnark.get_constraint_system();


    //zksnark part
    bp::Fisk<ppT> fisk;

    //generate
    r1cs_ppzksnark_keypair<ppT> keypair = fisk.generate(cs, true);

    //create test input
    const long int primary_input_vals[] = {0xd23caea};

    libsnark::r1cs_primary_input<FieldT> primary_input = generate_input<FieldT>(primary_input_vals, 1, 1);

    const long int aux_input[] = {'2', '1', '2', '1'};
    libsnark::r1cs_auxiliary_input<FieldT> auxiliary_input = generate_bit_vec_input<FieldT>(aux_input, 4, cs.auxiliary_input_size);

    libsnark::r1cs_auxiliary_input<FieldT> aux_input_v2 = webstrateSnark.generate_r1cs_witness(primary_input, auxiliary_input);

    //prove
    libsnark::r1cs_ppzksnark_proof<ppT> proof = fisk.prove(keypair.pk, primary_input, aux_input_v2, true);

    //verify
    bool ans = fisk.verify(keypair.vk, primary_input, proof);
    assert(ans);

}

int main(int argc, const char * argv[])
{
    default_r1cs_ppzksnark_pp::init_public_params();
    libff::start_profiling();


    test_r1cs_minimal<default_r1cs_ppzksnark_pp>(512);
}