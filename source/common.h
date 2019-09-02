/////////////////////////////////////////////////////////////////////////
//
// Author: Mateusz Jurczyk (mjurczyk@google.com)
//
// Copyright 2019 Google LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#ifndef DRSANCOV_COMMON_H_
#define DRSANCOV_COMMON_H_

#include <inttypes.h>

#include <cstdio>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif  // MAX_PATH

// Magic values found at the beginning of .sancov files to define their bitness.
// See https://clang.llvm.org/docs/SanitizerCoverage.html#sancov-data-format.
#if __LP64__ || defined(_WIN64)
#define WORDSIZE 64
#define SANCOV_MAGIC 0xC0BFFFFFFFFFFF64ULL
#else
#define WORDSIZE 32
#define SANCOV_MAGIC 0xC0BFFFFFFFFFFF32ULL
#endif

// Kills the process instantly on a critical error.
void Die(const char *format, ...);

// Prints the specified message to the output log file and stderr.
void Log(FILE *output_log, const char *format, ...);

// Returns a string corresponding to the Linux signal number, or NULL for
// unsupported signals.
const char *SignalString(int sig);

#endif  // DRSANCOV_COMMON_H_
