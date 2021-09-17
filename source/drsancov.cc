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

#include <signal.h>
#include <unistd.h>

#include <cinttypes>
#include <cstring>
#include <unordered_set>
#include <vector>

#include <dr_api.h>
#include <dr_events.h>
#include <drmgr.h>

#include "common.h"
#include "tokenizer.h"

////////////////////////////////////////////////////////////////////////////////
//
// DynamoRIO callback declarations.
//
////////////////////////////////////////////////////////////////////////////////

void EventExit(void);
dr_emit_flags_t EventBasicBlock(void *drcontext, void *tag, instrlist_t *bb,
    instr_t *inst, bool for_trace, bool translating, void *user_data);
dr_signal_action_t EventSignal(void *drcontext, dr_siginfo_t *siginfo);
void EventModuleLoad(void *drcontext, const module_data_t *info, bool loaded);
void EventModuleUnload(void *drcontext, const module_data_t *info);

////////////////////////////////////////////////////////////////////////////////
//
// Structure definitions and global objects.
//
////////////////////////////////////////////////////////////////////////////////

struct Configuration {
  // Indicates if code coverage collection is enabled, as configured through the
  // standard ASAN_OPTIONS environment variable:
  //
  // ASAN_OPTIONS=coverage=1
  //
  // Default: false
  bool coverage_enabled;

  // Stores the value of the exit code expected of the subprocess when an ASAN
  // crash occurs, configured through the exitcode switch in the ASAN_OPTIONS
  // environment variable:
  //
  // ASAN_OPTIONS=coverage=1,exitcode=11
  //
  // Default: 42
  int exitcode;

  // Stores the path to a file which should contain an ASAN-like report if a
  // crash occurs. It is configured through the log_path switch in ASAN_OPTIONS:
  //
  // ASAN_OPTIONS=coverage=1,log_path=/path/to/file
  //
  // Default: ""
  std::string log_path;

  // Stores the output directory path for the *.sancov files produced by the
  // instrumentation. It is configured through the coverage_dir switch in the
  // ASAN_OPTIONS environment variable:
  //
  // ASAN_OPTIONS=coverage=1,coverage_dir=/path/to/directory
  //
  // Default: "." (current directory)
  std::string coverage_dir;

  // Indicates if executed addresses that can't be associated with any
  // executable images (e.g. mmapped memory) should also be logged under the
  // "unknown" module:
  //
  // LOG_UNKNOWN_ADDRESSES=1
  //
  // Default: false (instructions outside of modules are not logged)
  bool log_unknown_addresses;
};

struct ModuleInfo {
  // Is the module currently loaded in memory?
  bool loaded;

  // Base address and size.
  size_t base;
  size_t size;

  // Number of unique traces encountered in the module.
  unsigned int trace_count;

  // A bitmap indicating basic blocks visited in the code.
  bool *bitmap;

  // Internal DynamoRIO module information.
  module_data_t *info;
};

namespace globals {

// Information about all modules ever loaded in the process address space.
static std::vector<ModuleInfo> modules;

// Synchronization lock guarding access to global objects.
static void *mod_lock;

// A pointer to an object storing globally-accessible internal structures.
// These structures are not destroyed before the death of the process.
static Configuration *config;

// Information about all executed instructions which don't belong to executable
// images, but e.g. to RWX mmap-ed memory areas etc.
static std::unordered_set<size_t> unclassified_traces;

}  // namespace globals

////////////////////////////////////////////////////////////////////////////////
//
// Helper functions.
//
////////////////////////////////////////////////////////////////////////////////

static void ParseEnvironmentConfig() {
  const char *log_unknown_addrs_ptr = getenv("LOG_UNKNOWN_ADDRESSES");
  if (log_unknown_addrs_ptr != nullptr &&
      atoi(log_unknown_addrs_ptr) != 0) {
    globals::config->log_unknown_addresses = true;
  }

  const char *asan_options_ptr = getenv("ASAN_OPTIONS");
  if (asan_options_ptr == nullptr) {
    return;
  }

  std::string asan_options(asan_options_ptr);
  std::vector<std::pair<std::string, std::string>> tokens;
  if (!TokenizeString(asan_options, &tokens)) {
    Die("Unable to parse the ASAN_OPTIONS environment variable.\n");
  }

  for (const auto& it : tokens) {
    if (it.first == "coverage") {
      globals::config->coverage_enabled = (atoi(it.second.c_str()) != 0);
    } else if (it.first == "exitcode") {
      globals::config->exitcode = atoi(it.second.c_str());
    } else if (it.first == "log_path") {
      globals::config->log_path = it.second + "." + std::to_string(getpid());
    } else if (it.first == "coverage_dir") {
      globals::config->coverage_dir = it.second;
    }
  }
}

static int FindModuleByAddress(size_t address) {
  for (int i = 0; i < globals::modules.size(); i++) {
    if (globals::modules[i].loaded &&
        globals::modules[i].base <= address &&
        globals::modules[i].base + globals::modules[i].size > address) {
      return i;
    }
  }
  return -1;
}

static bool EqualModules(const module_data_t *d1, const module_data_t *d2) {
  if (d1->start == d2->start && d1->end == d2->end &&
      d1->entry_point == d2->entry_point &&
      dr_module_preferred_name(d1) != NULL &&
      dr_module_preferred_name(d2) != NULL &&
      !strcmp(dr_module_preferred_name(d1), dr_module_preferred_name(d2))) {
    return true;
  }

  return false;
}

////////////////////////////////////////////////////////////////////////////////
//
// DynamoRIO callback declarations.
//
////////////////////////////////////////////////////////////////////////////////

DR_EXPORT void dr_init(client_id_t id) {
  // Initialize the configuration object with sane defaults.
  globals::config = new Configuration;
  globals::config->coverage_enabled = false;
  globals::config->exitcode = 42;
  globals::config->log_path = "";
  globals::config->coverage_dir = ".";
  globals::config->log_unknown_addresses = false;

  // Initialize the configuration data based on the environment variables.
  ParseEnvironmentConfig();

  // Create a mutex for synchronization.
  globals::mod_lock = dr_mutex_create();

  // Register standard callbacks.
  drmgr_init();
  drmgr_register_signal_event(EventSignal);
  drmgr_register_module_load_event(EventModuleLoad);
  drmgr_register_module_unload_event(EventModuleUnload);
  dr_register_exit_event(EventExit);

  // Only register basic-block instrumentation if coverage collection is
  // enabled.
  if (globals::config->coverage_enabled) {
    drmgr_register_bb_instrumentation_event(NULL, EventBasicBlock, NULL);
  }

  // Set other DynamoRIO properties.
  disassemble_set_syntax(DR_DISASM_INTEL);
}

void EventExit(void) {
  const uint64_t kMagic = SANCOV_MAGIC;
  FILE *f;

  dr_mutex_lock(globals::mod_lock);

  for (int i = 0; i < globals::modules.size(); i++) {
    // Skip modules with no coverage information, system modules and the loader
    // image.
    if (globals::modules[i].trace_count == 0 ||
        !strncmp(globals::modules[i].info->full_path, "/lib", 4)) {
      continue;
    }

    const char *preferred_name = dr_module_preferred_name(globals::modules[i].info);
    const char *ignored_list[] = {
      "ld-linux.so",
      "ld-linux-x86-64.so",
      "libstdc++.so",
      "linux-gate.so",
      "libc.so",
      "libgcc_s.so",
      "libm.so",
      "libc++.so",
      "libc++abi.so",
      "libdl.so",
      "libpthread.so",
      NULL
    };

    bool ignored = false;
    for (int j = 0; ignored_list[j] != NULL; j++) {
      if (!strncmp(preferred_name, ignored_list[j], strlen(ignored_list[j]))) {
        ignored = true;
        break;
      }
    }

    if (ignored) {
      continue;
    }

    const std::string sancov_path =
        globals::config->coverage_dir + "/" + preferred_name + "." +
        std::to_string(getpid()) + ".sancov";

    f = fopen(sancov_path.c_str(), "w+b");
    if (f != NULL) {
      fwrite(&kMagic, sizeof(kMagic), 1, f);

      for (int j = 0; j < globals::modules[i].size; j++) {
        if (globals::modules[i].bitmap[j]) {
          size_t trace = j;
          fwrite(&trace, sizeof(trace), 1, f);
        }
      }

      fclose(f);

      fprintf(stderr, "DrSanitizerCoverage: %s: %d PCs written\n",
              sancov_path.c_str(), globals::modules[i].trace_count);
    } else {
      fprintf(stderr, "[-] Unable to write to the \"%s\" log file\n",
              sancov_path.c_str());
    }

    free(globals::modules[i].bitmap);
  }

  if (!globals::unclassified_traces.empty()) {
    std::string sancov_path =
        globals::config->coverage_dir + "/unknown." + std::to_string(getpid()) +
        ".sancov";

    f = fopen(sancov_path.c_str(), "w+b");
    if (f != NULL) {
      fwrite(&kMagic, sizeof(kMagic), 1, f);

      for (size_t trace : globals::unclassified_traces) {
        fwrite(&trace, sizeof(trace), 1, f);
      }

      fclose(f);

      fprintf(stderr, "DrSanitizerCoverage: %s: %zu PCs written\n",
              sancov_path.c_str(), globals::unclassified_traces.size());
    } else {
      fprintf(stderr, "[-] Unable to write to the \"%s\" log file\n",
              sancov_path.c_str());
    }
  }

  dr_mutex_unlock(globals::mod_lock);
  dr_mutex_destroy(globals::mod_lock);

  drmgr_exit();
}

dr_emit_flags_t EventBasicBlock(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                                bool for_trace, bool translating, void *user_data) {
  const size_t pc = (size_t)tag;
  static int last_idx = -1;

  if (!drmgr_is_first_instr(drcontext, inst)) {
    return DR_EMIT_DEFAULT;
  }

  if (last_idx != -1 &&
      (globals::modules[last_idx].base > pc ||
       globals::modules[last_idx].base + globals::modules[last_idx].size <= pc)) {
    last_idx = -1;
  }

  if (last_idx == -1) {
    last_idx = FindModuleByAddress(pc);
  }

  if (last_idx == -1) {
    if (globals::config->log_unknown_addresses) {
      globals::unclassified_traces.insert(pc);
    }
  } else {
    if (globals::modules[last_idx].bitmap[pc - globals::modules[last_idx].base] == 0) {
      globals::modules[last_idx].bitmap[pc - globals::modules[last_idx].base] = 1;
      globals::modules[last_idx].trace_count++;
    }
  }

  return DR_EMIT_DEFAULT;
}

dr_signal_action_t EventSignal(void *drcontext, dr_siginfo_t *siginfo) {
  // Whether the signal is supported determines if we are pretending to print
  // out an ASAN-like report (to be treated like an ASAN crash), or if we just
  // print an arbitrary report and continue with the exception to be caught by
  // the fuzzer as-is.
  const char *signal_string = SignalString(siginfo->sig);
  const bool asan_crash = (signal_string != NULL);
  const void *orig_pc = siginfo->mcontext->pc;
  dr_mcontext_t *ctx;

  if (siginfo->raw_mcontext_valid) {
    ctx = siginfo->raw_mcontext;
  } else {
    ctx = siginfo->mcontext;
  }

  // If requested by the user, open the output log file.
  FILE *output_log = NULL;
  if (!globals::config->log_path.empty() && asan_crash) {
    output_log = fopen(globals::config->log_path.c_str(), "w+");
  }

  if (asan_crash) {
    Log(output_log, "ASAN:SIG%s\n"
                    "=================================================================\n"
                    "==%d==ERROR: AddressSanitizer: %s on unknown address 0x%zx "
                    "(pc 0x%zx sp 0x%zx bp 0x%zx T0)\n",
                    signal_string, getpid(), signal_string, (size_t)siginfo->access_address,
                    orig_pc, ctx->xsp, ctx->xbp);

    const char *module = "???";
    size_t offset = (size_t)orig_pc;
    const int module_idx = FindModuleByAddress((size_t)orig_pc);

    if (module_idx != -1) {
      module = dr_module_preferred_name(globals::modules[module_idx].info);
      offset = (size_t)orig_pc - globals::modules[module_idx].base;
    }

    Log(output_log, "    #0 0x%zx in %s+%x\n", orig_pc, module, offset);
  } else {
    Log(output_log, "======================================== %s\n",
                    strsignal(siginfo->sig));
  }

  Log(output_log, "\n==%d==CONTEXT\n", getpid());
#if WORDSIZE == 32
  Log(output_log,
          "  eax=%.8x ebx=%.8x ecx=%.8x edx=%.8x esi=%.8x edi=%.8x\n"
          "  eip=%.8x esp=%.8x ebp=%.8x eflags=%.8x\n",
          ctx->xax, ctx->xbx, ctx->xcx, ctx->xdx, ctx->xsi, ctx->xdi,
          ctx->pc, ctx->xsp, ctx->xbp, ctx->xflags);
#else  // WORDSIZE == 64
  Log(output_log,
          "  rax=%.16llx rbx=%.16llx rcx=%.16llx rdx=%.16llx\n"
          "  rsi=%.16llx rdi=%.16llx rsp=%.16llx rbp=%.16llx\n"
          "   r8=%.16llx  r9=%.16llx r10=%.16llx r11=%.16llx\n"
          "  r12=%.16llx r13=%.16llx r14=%.16llx r15=%.16llx\n"
          "  rip=%.16llx rflags=%.16llx\n",
          ctx->xax, ctx->xbx, ctx->xcx, ctx->xdx,
          ctx->xsi, ctx->xdi, ctx->xsp, ctx->xbp,
          ctx->r8,  ctx->r9,  ctx->r10, ctx->r11,
          ctx->r12, ctx->r13, ctx->r14, ctx->r15,
          ctx->pc, ctx->xflags);
#endif

  if (siginfo->sig == SIGSEGV) {
    Log(output_log, "Accessed address: 0x%zx\n", siginfo->access_address);
  }

  if (siginfo->raw_mcontext_valid) {
    Log(output_log, "Faulting code:\n");

    char disasm[128];
    int printed;
    disassemble_to_buffer(drcontext, ctx->pc, ctx->pc,
                          /*show_pc=*/true, /*show_bytes=*/false,
                          disasm, sizeof(disasm), &printed);

    Log(output_log, "%s\n", disasm);
  }

  Log(output_log, "==%d==ABORTING\n", getpid());

  if (output_log != NULL) {
    fclose(output_log);
  }

  // Exit with the special exitcode to inform the fuzzer that a crash has
  // occurred.
  if (asan_crash) {
    exit(globals::config->exitcode);
  }

  // Never reached.
  return DR_SIGNAL_DELIVER;
}

void EventModuleLoad(void *drcontext, const module_data_t *info, bool loaded) {
  int i;

  dr_mutex_lock(globals::mod_lock);

  for (i = 0; i < globals::modules.size(); i++) {
    if (!globals::modules[i].loaded && EqualModules(globals::modules[i].info, info)) {
      globals::modules[i].loaded = true;
      break;
    }
  }

  if (i == globals::modules.size()) {
    ModuleInfo module;
    module.loaded      = true;
    module.base        = (size_t)info->start;
    module.size        = (size_t)info->end - (size_t)info->start;
    module.trace_count = 0;
    module.bitmap      = (bool *)malloc(module.size);
    module.info        = dr_copy_module_data(info);

    globals::modules.push_back(module);
  }

  dr_mutex_unlock(globals::mod_lock);
}

void EventModuleUnload(void *drcontext, const module_data_t *info) {
  int i;

  dr_mutex_lock(globals::mod_lock);

  for (i = 0; i < globals::modules.size(); i++) {
    if (globals::modules[i].loaded && EqualModules(globals::modules[i].info, info)) {
      globals::modules[i].loaded = false;
      break;
    }
  }

  dr_mutex_unlock(globals::mod_lock);
}

