if [[ $1 == "compile" ]]; then
    cd build
    make test_rust_bridge
    cd ..
fi
# ./build/libsnark/jsnark_interface/print_r1cs gg Sudoku9x9.arith Sudoku9x9_Sample_Run1.in > sudoku.txt
./build/libsnark/jsnark_interface/test_rust_bridge dot.arith dot.in