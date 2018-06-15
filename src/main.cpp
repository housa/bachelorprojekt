//#define DEBUG true

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

#include <iostream>
#include <fstream>
#include <string>

#include <chrono>

using namespace libsnark;


template<typename ppT>
void test_r1cs_minimal(size_t input_size)
{

    typedef default_r1cs_ppzksnark_pp detype;
    typedef libff::Fr<detype> FieldT;

    bool test_serialization = false;

    std::chrono::nanoseconds prove_start, prove_end,
            verify_start, verify_end,
            gen_start, gen_end;

    //R1CS part
    bp::WebstrateSnark<FieldT> webstrateSnark(input_size);
    webstrateSnark.generate_r1cs_constraints();

    webstrateSnark.set_num_of_inputs(8);

    libsnark::r1cs_constraint_system<FieldT> cs = webstrateSnark.get_constraint_system();

    //zksnark part
    bp::Fisk<ppT> fisk;

    //generate
    gen_start = std::chrono::duration_cast< std::chrono::nanoseconds >(
            std::chrono::system_clock::now().time_since_epoch()
    );

    r1cs_ppzksnark_keypair<ppT> keypair = fisk.generate(cs, test_serialization);

    gen_end = std::chrono::duration_cast< std::chrono::nanoseconds >(
            std::chrono::system_clock::now().time_since_epoch()
    );

    //create test input
    std::vector<U32> aux_input;
    read_file_to_int_vector("input.txt", aux_input, input_size / 32);

    std::cout << aux_input.size() << " : aux_input.size() \n";

    std::vector<U32> aux_input_hashed;
    bp::sha<FieldT>(aux_input, aux_input_hashed, input_size);

    libsnark::r1cs_auxiliary_input<FieldT> auxiliary_input = generate_bit_vec_input<FieldT>(aux_input, cs.auxiliary_input_size);
    libsnark::r1cs_primary_input<FieldT> primary_input = generate_input<FieldT>(aux_input_hashed, 8);

    libsnark::r1cs_auxiliary_input<FieldT> aux_input_v2 = webstrateSnark.generate_r1cs_witness(primary_input, auxiliary_input);

    //prove
     prove_start = std::chrono::duration_cast< std::chrono::nanoseconds >(
            std::chrono::system_clock::now().time_since_epoch()
    );

    libsnark::r1cs_ppzksnark_proof<ppT> proof = fisk.prove(keypair.pk, primary_input, aux_input_v2, test_serialization);

    prove_end = std::chrono::duration_cast< std::chrono::nanoseconds >(
            std::chrono::system_clock::now().time_since_epoch()
    );


    //verify
    verify_start = std::chrono::duration_cast< std::chrono::nanoseconds >(
            std::chrono::system_clock::now().time_since_epoch()
    );
    bool ans = fisk.verify(keypair.vk, primary_input, proof);
    assert(ans);

    verify_end = std::chrono::duration_cast< std::chrono::nanoseconds >(
            std::chrono::system_clock::now().time_since_epoch()
    );

    std::ofstream benchFile;
    benchFile.open("benchmark.txt", std::ios_base::app);
    benchFile << input_size << "\t" << (gen_end.count()-gen_start.count()) << "\t" << (prove_end.count()-prove_start.count()) << "\t" << (verify_end.count()-verify_start.count()) << "\n";
    benchFile.close();






}

int main(int argc, const char * argv[])
{
    default_r1cs_ppzksnark_pp::init_public_params();
    libff::start_profiling();

    U32 s = 10, e = 15;
    U32 n = 5;

    for (U32 j = s; j <= e; ++j) {
        for (U32 k = 0; k < 5; ++k) {
            std::cout << (1<<j);
            test_r1cs_minimal<default_r1cs_ppzksnark_pp>(1 << j);
        }
    }
}