#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>


/// `Instance` holds the description of R1CS matrices
struct Instance;

/// `NIZK` holds a proof produced by Spartan NIZK
struct NIZK;

/// `NIZKGens` holds public parameters for producing and verifying proofs with the Spartan NIZK
struct NIZKGens;

struct SpartanFieldElement {
  uint8_t val[32];
};

struct Entry {
  size_t row;
  size_t col;
  SpartanFieldElement element;
};

struct SpartanMatrix {
  const Entry *val;
  size_t size;
};

struct SpartanR1CSMatrixs {
  SpartanMatrix A;
  SpartanMatrix B;
  SpartanMatrix C;
};

struct SpartanAssignment {
  const SpartanFieldElement *val;
  size_t size;
};


extern "C" {

void nizk_generate(SpartanR1CSMatrixs matrixs,
                   SpartanAssignment var_assignment,
                   SpartanAssignment input_assignment,
                   size_t num_constraints,
                   char *gens_path,
                   char *inst_path);

void nizk_prove(NIZKGens *gens,
                Instance *inst,
                SpartanAssignment var_assignment,
                SpartanAssignment input_assignment,
                char *proof_path);

NIZKGens *nizk_read_gens(char *gens_path);

Instance *nizk_read_inst(char *inst_path);

NIZK *nizk_read_proof();

void nizk_test(SpartanR1CSMatrixs matrixs,
               SpartanAssignment var_assignment,
               SpartanAssignment input_assignment,
               size_t num_constraints);

bool nizk_verify(NIZKGens *gens, Instance *inst, NIZK *proof, SpartanAssignment input_assignment);

} // extern "C"
