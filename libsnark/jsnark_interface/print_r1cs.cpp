/*
 * print_r1cs.cpp * *      Author: Arasu Arun
 */

#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp> #include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>

/* The matrix will printed as groups of the following lines:
 * con count
 * index
 * coeff
 * index
 * coeff
 *
 * Here, con is the constraint number (row number of matrix)
 * count is the number of non-zero values in the constraint.
 * index, coeff are the non-zeros values of that row. 
 *
 */

void print_matrix(std::vector<r1cs_constraint<FieldT>> constraints, int num_variables, int num_inputs, char which) {
	// loop through all constraints
	for (int i=0; i<constraints.size(); i++) {
		r1cs_constraint<FieldT> constraint = constraints.at(i);

		linear_combination<FieldT> row;
		switch(which) {
			case 'A': 
				row = constraint.a;
				break;
			case 'B':
				row = constraint.b;
				break;
			case 'C': 
				row = constraint.c;
				break;
		}

		std::vector<linear_term<FieldT>> entries = row.terms;
		for (int j=0; j<entries.size(); j++) {
			// constraint_num  index coeff 

			// the next lines adjust for the difference in notation between xJsnark, Spartan
			// xJsnark: (1, inputs, vars)
			// Spartan: (vars, 1, inputs)
			
			int true_index = entries.at(j).index;
			if (true_index <= num_inputs) {
				true_index += num_variables;
			} else {
				true_index -= (num_inputs+1);
			}
			cout << i << " " <<  true_index << " ";
			entries.at(j).coeff.print();
		}
	}
}


int main(int argc, char **argv) {

	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);

	int inputStartIndex = 0;
	if(argc == 4){
		if(strcmp(argv[1], "gg") != 0){
			cout << "Invalid Argument - Terminating.." << endl;
			return -1;
		} else{
			cout << "Using ppzsknark in the generic group model [Gro16]." << endl;
		}
		inputStartIndex = 1;	
	} 	

	// Read the circuit, evaluate, and translate constraints
	libff::enter_block("Construct Reader");
	CircuitReader reader(argv[1 + inputStartIndex], argv[2 + inputStartIndex], pb);
	libff::leave_block("Construct Reader");
	libff::enter_block("Get CS");
	r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(
			*pb);
	libff::leave_block("Get CS");


	libff::enter_block("Output file");
	const r1cs_variable_assignment<FieldT> full_assignment =
			get_variable_assignment_from_gadgetlib2(*pb);
	
	cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
	cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

	// extract primary and auxiliary input
	const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),
			full_assignment.begin() + cs.num_inputs());
	const r1cs_auxiliary_input<FieldT> auxiliary_input(
			full_assignment.begin() + cs.num_inputs(), full_assignment.end());
	// Print R1CS Matrices
	std::vector<r1cs_constraint<FieldT> > constraints = cs.constraints;
	// Number of constraints
	cout << cs.num_constraints() << endl;
	// Number of variables
	cout << cs.num_variables() << endl;
	// Number of inputs
	cout << cs.num_inputs() << endl;
	int num_inputs = cs.num_inputs();
	int num_variables = cs.num_variables()-num_inputs;
	cout << "New Matrix A" << endl;
	print_matrix(constraints, num_variables, num_inputs, 'A');
	cout << "New Matrix B" << endl;
	print_matrix(constraints, num_variables, num_inputs, 'B');
	cout << "New Matrix C" << endl;
	print_matrix(constraints, num_variables, num_inputs, 'C');
	cout << "New Input Vector" << endl;
	for (int i=0; i < full_assignment.size(); i++) {
		full_assignment.at(i).as_bigint();
	}
	libff::leave_block("Output file");

	return 0;
}
