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
  cout << "check point 2" << endl;
	vector<vector<Entry>> result = {vector<Entry>(), vector<Entry>(), vector<Entry>()};
	for (int i=0; i<constraints.size(); i++) {
		r1cs_constraint<FieldT> constraint = constraints.at(i);
		vector<linear_combination<FieldT>> rows = {constraint.a, constraint.b, constraint.c};
		for (int j = 0; j < rows.size(); j++) {
			linear_combination<FieldT> row = rows[j];
			std::vector<linear_term<FieldT>> entries = row.terms;
			for (auto e: entries) {
				// constraint_num  index coeff 

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
  cout << "check point 2" << endl;
  Entry* matrix_A = new Entry[result[0].size()];
  for (int i = 0; i < result[0].size(); i++) {
    matrix_A[i] = result[0][i];
  }
  Entry* matrix_B = new Entry[result[1].size()];
  for (int i = 0; i < result[1].size(); i++) {
    matrix_B[i] = result[1][i];
  }
  Entry* matrix_C = new Entry[result[2].size()];
  for (int i = 0; i < result[2].size(); i++) {
    matrix_C[i] = result[2][i];
  }
	return {
    {matrix_A, result[0].size()},
    {matrix_B, result[1].size()},
    {matrix_C, result[2].size()}
  };
}

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
	int data_n = libff::dalek_r_limbs;
  cout << "check point 1" << endl;
  SpartanFieldElement* spartan_full_assignment = new SpartanFieldElement[full_assignment.size()];
  memset(spartan_full_assignment, 0, full_assignment.size() * sizeof(SpartanFieldElement));
  for (int i = 0; i < full_assignment.size(); i++) {
    spartan_full_assignment[i] = field_t_to_spartan(full_assignment[i]);
	};
  cout << "check point 1" << endl;
  size_t num_inputs = reader.getNumInputs() + reader.getNumOutputs();
  size_t num_variables = full_assignment.size() - num_inputs;
  SpartanFieldElement* input_assignment = new SpartanFieldElement[num_inputs];
  SpartanFieldElement* var_assignment = new SpartanFieldElement[num_variables];
  cout << "check point 1" << endl;
  for (int i = 0; i < num_inputs; i++) {
    input_assignment[i] = spartan_full_assignment[i];
  }
  cout << "check point 1" << endl;
  for (int i = 0; i < num_variables; i++) {
    var_assignment[i] = spartan_full_assignment[i + num_inputs];
  }
  cout << "check point 1" << endl;
  SpartanR1CSMatrixs matrixs = get_matrixs(cs.constraints, num_variables, num_inputs);
  nizk_test(matrixs, {var_assignment, num_variables}, {input_assignment, num_inputs}, cs.num_constraints());
  // test_fn(num_inputs / 32, input_assignment);
  // cout << num_inputs / 32;
}
