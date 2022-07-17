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
		gadgetlib2::initPublicParamsFromDefaultPp();
		gadgetlib2::GadgetLibAdapter::resetVariableIndex();
		std::ifstream istrm(pk_path, std::ios::binary);
		r1cs_gg_ppzksnark_proving_key<Dpp>* pk = new r1cs_gg_ppzksnark_proving_key<Dpp>();
		istrm >> *pk;
		return pk;
	}

	void generate_proof(char* arith_path, char* in_path, char* proof_path, r1cs_gg_ppzksnark_proving_key<Dpp>* pk)
	{
		libff::start_profiling();
		gadgetlib2::GadgetLibAdapter::resetVariableIndex();
		ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);
		// Read the circuit, evaluate, and translate constraints
		CircuitReader reader(arith_path, in_path, pb);
		// r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(
		// 	*pb);
		libff::enter_block("get full assignment");
		const r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*pb);
		libff::leave_block("get full assignment");
		// cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
		// cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

		// extract primary and auxiliary input
		const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),
													   full_assignment.begin() + 165);
		const r1cs_auxiliary_input<FieldT> auxiliary_input(
			full_assignment.begin() + 165, full_assignment.end());

		// r1cs_example<FieldT> example(cs, primary_input, auxiliary_input);
		r1cs_gg_ppzksnark_proof<Dpp> proof = r1cs_gg_ppzksnark_prover<Dpp>(*pk, primary_input, auxiliary_input);
		std::ofstream ostrm(proof_path, std::ios::binary);
    	ostrm << proof;
	}

	r1cs_gg_ppzksnark_processed_verification_key<Dpp>* read_pvk(const char* pvk_path) {
		gadgetlib2::initPublicParamsFromDefaultPp();
		gadgetlib2::GadgetLibAdapter::resetVariableIndex();
		std::ifstream istrm2(pvk_path, std::ios::binary);
		r1cs_gg_ppzksnark_processed_verification_key<Dpp>* pvk = new r1cs_gg_ppzksnark_processed_verification_key<Dpp>();
		istrm2 >> *pvk;
		return pvk;
	}

	bool verify_proof(char* public_inputs, char* proof_binary, int proof_len, r1cs_gg_ppzksnark_processed_verification_key<Dpp>* pvk) {
		gadgetlib2::GadgetLibAdapter::resetVariableIndex();
		r1cs_gg_ppzksnark_proof<Dpp> proof;
		std::stringstream proofstream;
		for (int i = 0; i < proof_len; i++) {
			proofstream << proof_binary[i];
		}
		proofstream >> proof;
		vector<FieldT> my_primary_input;
		std::istringstream inputstream(public_inputs, ifstream::in);
		string line;
		char* inputStr;
		while (getline(inputstream, line)) {
			Wire wireId;
			inputStr = new char[line.size()];
			sscanf(line.c_str(), "%u %s", &wireId, inputStr);
			my_primary_input.push_back(readFieldElementFromHex(inputStr));
		}

		const bool ans = r1cs_gg_ppzksnark_online_verifier_strong_IC(*pvk, my_primary_input, proof);
		return ans;
	}
}