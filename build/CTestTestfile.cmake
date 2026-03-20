# CMake generated Testfile for 
# Source directory: /tmp/fuzz-binary-protocol_1774029605
# Build directory: /tmp/fuzz-binary-protocol_1774029605/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(ProtocolTest "/tmp/fuzz-binary-protocol_1774029605/build/test_fuzzer" "protocol")
set_tests_properties(ProtocolTest PROPERTIES  _BACKTRACE_TRIPLES "/tmp/fuzz-binary-protocol_1774029605/CMakeLists.txt;58;add_test;/tmp/fuzz-binary-protocol_1774029605/CMakeLists.txt;0;")
add_test(MutatorTest "/tmp/fuzz-binary-protocol_1774029605/build/test_fuzzer" "mutator")
set_tests_properties(MutatorTest PROPERTIES  _BACKTRACE_TRIPLES "/tmp/fuzz-binary-protocol_1774029605/CMakeLists.txt;59;add_test;/tmp/fuzz-binary-protocol_1774029605/CMakeLists.txt;0;")
add_test(FuzzerTest "/tmp/fuzz-binary-protocol_1774029605/build/test_fuzzer" "fuzzer")
set_tests_properties(FuzzerTest PROPERTIES  _BACKTRACE_TRIPLES "/tmp/fuzz-binary-protocol_1774029605/CMakeLists.txt;60;add_test;/tmp/fuzz-binary-protocol_1774029605/CMakeLists.txt;0;")
add_test(IntegrationTest "/tmp/fuzz-binary-protocol_1774029605/build/test_fuzzer" "integration")
set_tests_properties(IntegrationTest PROPERTIES  _BACKTRACE_TRIPLES "/tmp/fuzz-binary-protocol_1774029605/CMakeLists.txt;61;add_test;/tmp/fuzz-binary-protocol_1774029605/CMakeLists.txt;0;")
