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
// Description
// ===========
//
// Tokenizer of the ASAN_OPTIONS environment variable, used to extract
// particular flags controlling the behavior of the code coverage tracing. The
// code is mostly a rewritten version of the sanitizer_flag_parser.cc file, in
// order to stay compliant with the original ASAN flag parsing algorithm.

#ifndef DRSANCOV_TOKENIZER_H_
#define DRSANCOV_TOKENIZER_H_

#include <string>
#include <vector>

// Translates a serialized, textual representation of ASAN options to a list of
// (key, value) pairs.
bool TokenizeString(const std::string& buffer,
                    std::vector<std::pair<std::string, std::string>> *tokens);

#endif  // DRSANCOV_TOKENIZER_H_
