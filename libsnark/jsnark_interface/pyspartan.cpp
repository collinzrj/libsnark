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
#include "spartan_libsnark.h"

typedef libsnark::default_r1cs_gg_ppzksnark_pp Dpp;

using std::endl;

SpartanFieldElement field_t_to_spartan(FieldT f) {
  SpartanFieldElement result;
  // libff::dalek_r_limbs
  // hardcoded to 4 here, need to change for different curve
  for (int j = 0; j < 4; j++) {
    unsigned long current = f.as_bigint().data[j];
    // data is u64 in this case, which is 8 u8
    for (int k = 0; k < 8; k++) {
      result.val[j * 8 + k] = current % 256;
      current /= 256;
    }
  }
  return result;
}

SpartanR1CSMatrixs get_matrixs(vector<r1cs_constraint<FieldT>> constraints, int num_variables, int num_inputs) {
	vector<vector<Entry>> result = {vector<Entry>(), vector<Entry>(), vector<Entry>()};
	for (int i=0; i<constraints.size(); i++) {
		r1cs_constraint<FieldT> constraint = constraints.at(i);
		vector<linear_combination<FieldT>> rows = {constraint.a, constraint.b, constraint.c};
		for (int j = 0; j < rows.size(); j++) {
			linear_combination<FieldT> row = rows[j];
			std::vector<linear_term<FieldT>> entries = row.terms;
			for (auto e: entries) {
				// the next lines adjust for the difference in notation between xJsnark, Spartan
				// xJsnark: (1, inputs, vars)
				// Spartan: (vars, 1, inputs)				
				int true_index = e.index;
				if (true_index <= num_inputs) {
					true_index += num_variables;
				} else {
					true_index -= (num_inputs+1);
				}
				Entry entry = {i, true_index, field_t_to_spartan(e.coeff)};
				result[j].push_back(entry);
			}
		}
	}
  Entry* matrix_A = new Entry[result[0].size()];
  copy(result[0].begin(), result[0].end(), matrix_A);
  Entry* matrix_B = new Entry[result[1].size()];
  copy(result[1].begin(), result[1].end(), matrix_B);
  Entry* matrix_C = new Entry[result[2].size()];
  copy(result[2].begin(), result[2].end(), matrix_C);
	return {
    {matrix_A, result[0].size()},
    {matrix_B, result[1].size()},
    {matrix_C, result[2].size()}
  };
}

pair<SpartanAssignment, SpartanAssignment> get_assignments(r1cs_variable_assignment<FieldT> full_assignment, size_t num_variables, size_t num_inputs) {
  auto input_assignment = new SpartanFieldElement[num_inputs];
  auto var_assignment = new SpartanFieldElement[num_variables];
  for (int assign_idx = 0; assign_idx < num_inputs; assign_idx++) {
    input_assignment[assign_idx] = field_t_to_spartan(full_assignment[assign_idx]);
  }
  for (int assign_idx = 0; assign_idx < num_variables; assign_idx++) {
    var_assignment[assign_idx] = field_t_to_spartan(full_assignment[assign_idx + num_inputs]);
  }
  return { {var_assignment, num_variables}, {input_assignment, num_inputs}};
}

SpartanAssignment get_assignment(r1cs_variable_assignment<FieldT> assignment) {
	auto result = new SpartanFieldElement[assignment.size()];
	for (int assign_idx = 0; assign_idx < assignment.size(); assign_idx++) {
		result[assign_idx] = field_t_to_spartan(assignment[assign_idx]);
	}
	return {result, assignment.size()};
}

extern "C"
{
	void spartan_generate(char* arith_path, char* in_path, char* gens_path, char* inst_path) {
		gadgetlib2::initPublicParamsFromDefaultPp();
		gadgetlib2::GadgetLibAdapter::resetVariableIndex();
		ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);
		CircuitReader reader(arith_path, in_path, pb);
		auto cs = get_constraint_system_from_gadgetlib2(*pb);
		auto full_assignment = get_variable_assignment_from_gadgetlib2(*pb);
		size_t num_inputs = reader.getNumInputs() + reader.getNumOutputs();
		size_t num_variables = full_assignment.size() - num_inputs;
		auto assign_pair = get_assignments(full_assignment, num_variables, num_inputs);
		auto matrixs = get_matrixs(cs.constraints, num_variables, num_inputs);
		nizk_generate(matrixs, assign_pair.first, assign_pair.second, cs.num_constraints(), gens_path, inst_path);
	}

	NIZKGens* spartan_read_gens(char* gens_path) {
		return nizk_read_gens(gens_path);
	}

	Instance* spartan_read_inst(char* inst_path) {
		return nizk_read_inst(inst_path);
	}

	void spartan_prove(char* arith_path, char* in_path, char* proof_path, NIZKGens* gens, Instance* inst) {
		gadgetlib2::initPublicParamsFromDefaultPp();
		gadgetlib2::GadgetLibAdapter::resetVariableIndex();
		ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);
		CircuitReader reader(arith_path, in_path, pb);
		auto cs = get_constraint_system_from_gadgetlib2(*pb);
		auto full_assignment = get_variable_assignment_from_gadgetlib2(*pb);
		size_t num_inputs = reader.getNumInputs() + reader.getNumOutputs();
		size_t num_variables = full_assignment.size() - num_inputs;
		auto assign_pair = get_assignments(full_assignment, num_variables, num_inputs);
		nizk_prove(gens, inst, assign_pair.first, assign_pair.second, proof_path);
	}

	void spartan_verify(NIZKGens* gens, Instance* inst, char* public_inputs) {
		vector<FieldT> primary_input;
		std::istringstream inputstream(public_inputs, ifstream::in);
		string line;
		char* inputStr;
		while (getline(inputstream, line)) {
			Wire wireId;
			inputStr = new char[line.size()];
			sscanf(line.c_str(), "%u %s", &wireId, inputStr);
			primary_input.push_back(readFieldElementFromHex(inputStr));
		}
		auto proof = nizk_read_proof();
		nizk_verify(gens, inst, proof, get_assignment(primary_input));
	}
}