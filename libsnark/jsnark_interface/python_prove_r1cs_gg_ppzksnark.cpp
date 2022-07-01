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
#include <chrono>

typedef libsnark::default_r1cs_gg_ppzksnark_pp Dpp;

using std::endl;

extern "C"
{

	r1cs_gg_ppzksnark_proving_key<Dpp>* read_pk(const char* pk_path) {

		ios_base::sync_with_stdio(false);

		cout<< "begin read " << endl;

		gadgetlib2::initPublicParamsFromDefaultPp();
		gadgetlib2::GadgetLibAdapter::resetVariableIndex();
		std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
		std::ifstream istrm(pk_path, std::ios::binary);
		r1cs_gg_ppzksnark_proving_key<Dpp>* pk = new r1cs_gg_ppzksnark_proving_key<Dpp>();
		istrm >> *pk;
		std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();

		std::cout << "Time difference = " << std::chrono::duration_cast<std::chrono::seconds>(end - begin).count() << "[ns]" << endl;

		cout<< "end read" <<endl;
		return pk;
	}

	void generate_proof(char* arith_path, char* in_path, r1cs_gg_ppzksnark_proving_key<Dpp>* pk, char* proof_path)
	{
		libff::start_profiling();
		gadgetlib2::GadgetLibAdapter::resetVariableIndex();
		ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);
		// Read the circuit, evaluate, and translate constraints
		CircuitReader reader(arith_path, in_path, pb);
		r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(
			*pb);
		const r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*pb);
		cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
		cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

		// extract primary and auxiliary input
		const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),
													   full_assignment.begin() + cs.num_inputs());
		const r1cs_auxiliary_input<FieldT> auxiliary_input(
			full_assignment.begin() + cs.num_inputs(), full_assignment.end());

		r1cs_example<FieldT> example(cs, primary_input, auxiliary_input);
		r1cs_gg_ppzksnark_proof<Dpp> proof = r1cs_gg_ppzksnark_prover<Dpp>(*pk, example.primary_input, example.auxiliary_input);
		std::ofstream ostrm(proof_path, std::ios::binary);
		ostrm << proof;
	}

	void test_prove() {
		// r1cs_gg_ppzksnark_proving_key<Dpp>* pk = read_pk();;
		// generate_proof(pk);
	}
}