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
#include "suppe/utils.h"
#include "suppe/hash.h"

using namespace libsnark;


template<typename ppT>
void test_r1cs_minimal(size_t input_size)
{

    typedef default_r1cs_ppzksnark_pp detype;
    typedef libff::Fr<detype> FieldT;

    //R1CS part
    bp::WebstrateSnark<FieldT> webstrateSnark(input_size);
    webstrateSnark.generate_r1cs_constraints();

    webstrateSnark.set_num_of_inputs(8);

    libsnark::r1cs_constraint_system<FieldT> cs = webstrateSnark.get_constraint_system();



    //zksnark part
    bp::Fisk<ppT> fisk;

    //generate
    r1cs_ppzksnark_keypair<ppT> keypair = fisk.generate(cs, true);

    //create test input
    std::vector<U32> aux_input = {'2', '1', '2', '1'};

    std::vector<U32> aux_input_hashed;
    bp::sha<FieldT>(aux_input, aux_input_hashed);

    libsnark::r1cs_auxiliary_input<FieldT> auxiliary_input = generate_bit_vec_input<FieldT>(aux_input, cs.auxiliary_input_size);
    libsnark::r1cs_primary_input<FieldT> primary_input = generate_input<FieldT>(aux_input_hashed, 8);

    printf("primary_input = ");
    for (U32 j = 0; j < 8; ++j) {
        printf("%lx ", aux_input_hashed[j]);
    }
    printf("\n");

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