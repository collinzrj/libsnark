## Fork of libsnark for ZKMB project

`libsnark/jsnark_interface/pylibsnark.cpp` and `libsnark/jsnark_interface/pyspartan.cpp` are the two targets we should build

Before building `pylibsnark`, set the Curve to `BN128` in `CMAKELists.txt`

Before building `pyspartan`, set the Curve to `DALEK` in `CMAKELists.txt` 