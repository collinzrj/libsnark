#include <cstdint>
#include <stdio.h>

extern "C" {
  void test_fn(int size, int* arr);
}

int main() {
    // void* gens = nizk_generate();
    // nizk_prove(gens);

    int arr[10];
    for (int i = 0; i < 10; i++) {
        arr[i] = i * 100;
    }
    test_fn(10, arr);
}
