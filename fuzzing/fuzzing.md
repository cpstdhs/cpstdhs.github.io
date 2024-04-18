# fuzzing
- [fuzzing](#fuzzing)
  - [Libfuzzer](#libfuzzer)
  - [WinAFL](#winafl)
  - [Sanitizer](#sanitizer)

## Libfuzzer
> https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md

### Split inputs
> https://github.com/google/fuzzing/blob/master/docs/split-inputs.md
```c++
// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// A fuzzer that uses the FuzzedDataProvider library to consume fuzzing input.
// See also:
// https://github.com/google/fuzzing/blob/HEAD/docs/split-inputs.md#fuzzed-data-provider
// https://github.com/llvm/llvm-project/blob/HEAD/compiler-rt/include/fuzzer/FuzzedDataProvider.h
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <fuzzer/FuzzedDataProvider.h>
// The code under test. Normally this would be in a separate library.
namespace {
// In order to consume Enums in FuzzedDataProvider, your enums need to start at 0 and include an
// element named |kMaxValue|, equal to the maximum value of the enum.
enum Color {
  kRed = 0,
  kBlue,
  kYellow,
  kMaxValue = kYellow,
};
struct MyStruct {
  uint32_t my_int;
  double my_double;
  std::string my_str;
  Color my_color;
};
// Simulate a crash for a specific combinations of fields.
int crasher(uint16_t val1, uint8_t val2, bool val3, MyStruct *val4) {
  if (val4 != nullptr && val4->my_color == kBlue && val4->my_str.size() > 4) {
    __builtin_trap();
  }
  return 0;
}
}  // namespace
// The fuzz target function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  auto val1 = provider.ConsumeIntegralInRange<uint16_t>(13000, 16000);
  auto val2 = provider.ConsumeIntegral<uint8_t>();
  auto val3 = provider.ConsumeBool();
  MyStruct val4 = {
      .my_int = provider.ConsumeIntegral<uint32_t>(),
      .my_double = provider.ConsumeFloatingPoint<double>(),
      .my_color = provider.ConsumeEnum<Color>(),
  };
  val4.my_str = provider.ConsumeRemainingBytesAsString();
  return crasher(val1, val2, val3, &val4);
}
```

## WinAFL
## Sanitizer
- AddressSanitizer (detects addressability issues)
    > https://github.com/google/sanitizers/wiki/AddressSanitizer
- LeakSanitizer (detects memory leaks)
  > https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizer
- ThreadSanitizer (detects data races and deadlocks) for C++ and Go
  > https://github.com/google/sanitizers/wiki/ThreadSanitizerCppManual
- MemorySanitizer (detects use of uninitialized memory)
  > https://github.com/google/sanitizers/wiki/MemorySanitizer