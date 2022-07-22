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

template<typename T = void>
struct Vec;

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

void nizk_generate(Vec<Entry> matrix_A,
                   Vec<Entry> matrix_B,
                   Vec<Entry> matrix_C,
                   size_t num_constraints,
                   size_t num_variables,
                   size_t num_inputs);

void nizk_prove(NIZKGens *gens, Instance *inst, Vec<uint8_t[32]> vars, Vec<uint8_t[32]> inputs);

void nizk_test(SpartanR1CSMatrixs matrixs,
               SpartanAssignment var_assignment,
               SpartanAssignment input_assignment,
               size_t num_constraints);

bool nizk_verify(NIZKGens *gens, Instance *inst, NIZK *proof, Vec<uint8_t[32]> inputs);

} // extern "C"
