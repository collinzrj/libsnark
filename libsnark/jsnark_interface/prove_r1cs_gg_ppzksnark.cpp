/*
 * prove_r1cs_gg_ppzksnark.cpp
 *
 *      Author: Collin Zhang
 */

#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>

typedef libsnark::default_r1cs_gg_ppzksnark_pp Dpp;

int main(int argc, char **argv) {

	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);

	// Read the circuit, evaluate, and translate constraints
	CircuitReader reader(argv[1], argv[2], pb);
	r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(
			*pb);
	const r1cs_variable_assignment<FieldT> full_assignment =
			get_variable_assignment_from_gadgetlib2(*pb);
	cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
	cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

	// extract primary and auxiliary input
	const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),
			full_assignment.begin() + cs.num_inputs());
	const r1cs_auxiliary_input<FieldT> auxiliary_input(
			full_assignment.begin() + cs.num_inputs(), full_assignment.end());

	r1cs_example<FieldT> example(cs, primary_input, auxiliary_input);
	r1cs_gg_ppzksnark_proving_key<Dpp> pk;
	std::ifstream istrm(argv[3], std::ios::binary);
	istrm >> pk;
    r1cs_gg_ppzksnark_proof<Dpp> proof = r1cs_gg_ppzksnark_prover<Dpp>(pk, example.primary_input, example.auxiliary_input);
    std::ofstream ostrm(argv[4], std::ios::binary);
    ostrm << proof;
	return 0;
}

