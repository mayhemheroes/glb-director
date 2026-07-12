#include <stdint.h>
#include <stdio.h>
#include <climits>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>
#include "log.h"

/* Definition for the global `debug` flag declared extern in log.h.
 * glb_log_debug()/glb_log_level() read it; the harness never enables it. */
bool debug = false;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString(1000);

    /* Feed the fuzzed bytes as the log MESSAGE (a "%s" argument), not as the
     * format string itself: glb_log_info(fmt, ...) is a printf-style API whose
     * callers always control `fmt`, so passing attacker bytes directly as the
     * format would be an uncontrolled-format-string bug in the HARNESS, not in
     * the target. Driving it as data exercises the real code path — vsnprintf
     * truncation into message[MAX_MESSAGE_SZ] and glb_log_level()'s JSON build
     * (jansson UTF-8 validation of the message + json_dumps escaping). */
    glb_log_info("%s", str.c_str());

    return 0;
}
