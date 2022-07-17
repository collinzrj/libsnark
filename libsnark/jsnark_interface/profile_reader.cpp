#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <chrono>

int main(int argc, char **argv) {
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);
    // CircuitReader reader("/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/data/doh.arith", "/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/data/doh.in", pb);
	CircuitReader reader("/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/gen/circuits/Sudoku9x9.arith", 
						"/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/gen/circuits/Sudoku9x9_Sample_Run1.in", pb);
}