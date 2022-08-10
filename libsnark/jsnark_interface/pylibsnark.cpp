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
	void generate_pk_pvk(char* arith_path, char* pk_path, char* pvk_path) {
		libff::start_profiling();
		gadgetlib2::initPublicParamsFromDefaultPp();
		gadgetlib2::GadgetLibAdapter::resetVariableIndex();
		CircuitReader reader(arith_path);
		r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*reader.pb);
		const r1cs_variable_assignment<FieldT> full_assignment =
				get_variable_assignment_from_gadgetlib2(*reader.pb);
		cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
		cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

		// extract primary and auxiliary input
		const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),
				full_assignment.begin() + cs.num_inputs());
		const r1cs_auxiliary_input<FieldT> auxiliary_input(
				full_assignment.begin() + cs.num_inputs(), full_assignment.end());

		r1cs_example<FieldT> example(cs, primary_input, auxiliary_input);
		r1cs_gg_ppzksnark_keypair<Dpp> keypair = r1cs_gg_ppzksnark_generator<Dpp>(example.constraint_system);
		r1cs_gg_ppzksnark_processed_verification_key<Dpp> pvk = r1cs_gg_ppzksnark_verifier_process_vk<Dpp>(keypair.vk);
		r1cs_gg_ppzksnark_proving_key<Dpp> pk = keypair.pk;
	
		std::ofstream ostrm(pk_path, std::ios::binary);
		ostrm << pk;
		std::ofstream ostrm2(pvk_path, std::ios::binary);
		ostrm2 << pvk;
	}
	
	CircuitReader* read_circuit(char* arith_path) {
		CircuitReader* reader = new CircuitReader(arith_path);
		return reader;
	}

	r1cs_gg_ppzksnark_proving_key<Dpp>* read_pk(const char* pk_path) {
		// gadgetlib2::initPublicParamsFromDefaultPp();
		// gadgetlib2::GadgetLibAdapter::resetVariableIndex();
		std::ifstream istrm(pk_path, std::ios::binary);
		r1cs_gg_ppzksnark_proving_key<Dpp>* pk = new r1cs_gg_ppzksnark_proving_key<Dpp>();
		istrm >> *pk;
		return pk;
	}

	void initialize() {
		gadgetlib2::initPublicParamsFromDefaultPp();
		gadgetlib2::GadgetLibAdapter::resetVariableIndex();	
	}

	r1cs_gg_ppzksnark_processed_verification_key<Dpp>* read_pvk(const char* pvk_path) {
		// gadgetlib2::initPublicParamsFromDefaultPp();
		// gadgetlib2::GadgetLibAdapter::resetVariableIndex();
		std::ifstream istrm2(pvk_path, std::ios::binary);
		r1cs_gg_ppzksnark_processed_verification_key<Dpp>* pvk = new r1cs_gg_ppzksnark_processed_verification_key<Dpp>();
		istrm2 >> *pvk;
		return pvk;
	}
	
	pair<r1cs_primary_input<FieldT>, r1cs_auxiliary_input<FieldT>>* generate_proof_preprocess(CircuitReader* reader, char* in_path) {
		reader->parseInputFile(in_path);
		cout << "parse finish" << endl;
		const r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*reader->pb);
		cout << "get full assignment finish " << full_assignment.size() << endl;
		auto result = new pair<r1cs_primary_input<FieldT>, r1cs_auxiliary_input<FieldT>>; 
		size_t numInputs = reader->getNumInputs() + reader->getNumOutputs();
		for (int element_index = 0; element_index < numInputs; element_index++) {
			result->first.push_back(full_assignment[element_index]);
		}
		for (int element_index = numInputs; element_index < full_assignment.size(); element_index++) {
			result->second.push_back(full_assignment[element_index]);
		}
		cout << "primary size " << result->first.size() << endl;
		cout << "auxiliary size " << result->second.size() << endl; 
		return result;
	}

	// vector<int>* generate_proof_preprocess(CircuitReader* reader, char* in_path) {
	// 	vector<int>* result = new vector<int>();
	// 	result->push_back(8);
	// 	return result;
	// }

	void generate_proof(pair<r1cs_primary_input<FieldT>, r1cs_auxiliary_input<FieldT>>* assign_pair, r1cs_gg_ppzksnark_proving_key<Dpp>* pk, char* proof_path) {
		r1cs_gg_ppzksnark_proof<Dpp> proof = r1cs_gg_ppzksnark_prover<Dpp>(*pk, assign_pair->first, assign_pair->second);
		std::ofstream ostrm(proof_path, std::ios::binary);
    	ostrm << proof;
	}

	void verify_proof_benchmark(pair<r1cs_primary_input<FieldT>, r1cs_auxiliary_input<FieldT>>* assign_pair, r1cs_gg_ppzksnark_processed_verification_key<Dpp>* pvk, char* proof_path) {
		std::ifstream proofstream(proof_path, std::ios::binary);
		r1cs_gg_ppzksnark_proof<Dpp> proof;	
		proofstream >> proof;
		const bool ans = r1cs_gg_ppzksnark_online_verifier_strong_IC(*pvk, assign_pair->first, proof);
		cout << "verify ans is " << ans << endl;
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