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

void fuzz_shape_creation(FuzzedDataProvider &fdp) {
    Rect64 rect{fdp.ConsumeIntegral<int64_t>(), fdp.ConsumeIntegral<int64_t>(),
                fdp.ConsumeIntegral<int64_t>(), fdp.ConsumeIntegral<int64_t>()};
    auto ellipse = Ellipse(rect, fdp.ConsumeIntegral<uint8_t>());
}

void fuzz_path_function(FuzzedDataProvider &fdp) {
    Paths64 subject, clip, solution;
    FillRule fill_rule = static_cast<FillRule>(fdp.ConsumeIntegralInRange(0, max_fill_rule));
    subject.push_back(MakePath(fdp.ConsumeRandomLengthString().c_str()));
    clip.push_back(MakePath(fdp.ConsumeRandomLengthString().c_str()));

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
        case 3:
            Xor(subject, clip, fill_rule);
            break;
    }

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size) {
    FuzzedDataProvider fdp(data, size);
    auto fuzz_shapes = fdp.ConsumeBool();

    if (fuzz_shapes) {
        fuzz_shape_creation(fdp);
    } else {
        fuzz_path_function(fdp);
    }

    return 0;
}