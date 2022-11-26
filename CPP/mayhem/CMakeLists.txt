
add_executable(fuzz_clipper fuzz_clipper.cpp)

target_compile_options(fuzz_clipper PRIVATE -fsanitize=fuzzer,address)
target_link_options(fuzz_clipper PRIVATE -fsanitize=fuzzer,address)

target_link_libraries(fuzz_clipper Clipper2)