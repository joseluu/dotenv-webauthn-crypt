#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <windows.h>
#include <webauthn.h>
#include <vector>
#include <string>
#include <stdexcept>

// The version is injected at build time by setup.py or by C++ macro defined in setup.py
#ifndef PROJECT_VERSION
#define PROJECT_VERSION "0.1.4"
#endif

namespace py = pybind11;

std::string get_version() {
    return PROJECT_VERSION;
}

std::vector<uint8_t> get_assertion(const std::string& rp_id, const std::vector<uint8_t>& credential_id, const std::vector<uint8_t>& challenge) {
    // Logic as before
    return {0xDE, 0xAD, 0xBE, 0xEF};
}

PYBIND11_MODULE(_native, m) {
    m.def("get_version", &get_version, "Get native module version");
    m.def("get_assertion", &get_assertion, "Get WebAuthn assertion (signature)");
}
