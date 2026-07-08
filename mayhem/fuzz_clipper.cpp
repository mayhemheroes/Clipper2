#include <cstdint>
#include <vector>

#include "clipper2/clipper.h"

using namespace Clipper2Lib;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 16) return 0;

  const int64_t *vals = reinterpret_cast<const int64_t *>(data);
  size_t count = size / sizeof(int64_t);

  if (count < 4) return 0;

  size_t half = count / 2;
  if (half < 2) return 0;

  Path64 subject, clip;
  for (size_t i = 0; i + 1 < half; i += 2) {
    subject.push_back(Point64(vals[i] % 100000, vals[i + 1] % 100000));
  }
  for (size_t i = half; i + 1 < count; i += 2) {
    clip.push_back(Point64(vals[i] % 100000, vals[i + 1] % 100000));
  }

  if (subject.size() < 3 || clip.size() < 3) return 0;

  Paths64 subjects = {subject};
  Paths64 clips = {clip};

  Paths64 solution = Intersect(subjects, clips, FillRule::NonZero);
  solution = Union(subjects, clips, FillRule::NonZero);
  solution = Difference(subjects, clips, FillRule::NonZero);
  solution = Xor(subjects, clips, FillRule::NonZero);

  ClipperOffset co;
  co.AddPaths(subjects, JoinType::Round, EndType::Polygon);
  Paths64 result;
  co.Execute(5.0, result);

  return 0;
}
