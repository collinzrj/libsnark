/*
 * verify_r1cs_gg_ppzksnark.cpp
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
	// TODO: segmentation fault without this, why?
	gadgetlib2::initPublicParamsFromDefaultPp();
    // read pvk and proof from file
	r1cs_gg_ppzksnark_proof<Dpp> proof;
	std::ifstream istrm(argv[3], std::ios::binary);
	istrm >> proof;
	r1cs_gg_ppzksnark_processed_verification_key<Dpp> pvk;
	std::ifstream istrm2(argv[2], std::ios::binary);
	istrm2 >> pvk;
	vector<FieldT> my_primary_input;
	ifstream inputfs(argv[1], ifstream::in);
	string line;
	char* inputStr;
	for (int i = 0; i < 504; i++) {
		getline(inputfs, line);
		Wire wireId;
		inputStr = new char[line.size()];
		sscanf(line.c_str(), "%u %s", &wireId, inputStr);
		my_primary_input.push_back(readFieldElementFromHex(inputStr));
	}

    const bool ans = r1cs_gg_ppzksnark_online_verifier_strong_IC(pvk, my_primary_input, proof);
	printf("Ans is %d\n", ans);
    std::ofstream ostrm(argv[4], std::ios::binary);
    ostrm << ans;
	return ans;
}



