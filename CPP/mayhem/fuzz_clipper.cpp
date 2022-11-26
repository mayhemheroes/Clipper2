//
// Created by bailey on 11/26/22.
//
#include <cstdint>
#include <optional>

#include "clipper2/clipper.h"
#include "FuzzedDataProvider.h"

using namespace Clipper2Lib;


// Some constants needed for fuzzing decisions
constexpr const int max_fill_rule = 3;

void fuzz_path_function(FuzzedDataProvider &fdp) {
    Paths64 subject, clip, solution;
    auto fill_rule = static_cast<FillRule>(fdp.ConsumeIntegralInRange(0, max_fill_rule));
    subject.push_back(MakePath(fdp.ConsumeRandomLengthString()));
    clip.push_back(MakePath(fdp.ConsumeRandomLengthString()));

    int fuzz_func = fdp.ConsumeIntegralInRange(0, 3);

    switch (fuzz_func) {
        case 0:
            Intersect(subject, clip, fill_rule);
            break;
        case 1:
            Union(subject, clip, fill_rule);
            break;
        case 2:
            Difference(subject, clip, fill_rule);
            break;
        default:
            Xor(subject, clip, fill_rule);
            break;
    }
}

extern "C" [[maybe_unused]] int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size) {
    FuzzedDataProvider fdp(data, size);
    fuzz_path_function(fdp);

    return 0;
}