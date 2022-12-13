#include <stdint.h>
#include <stdio.h>
#include <climits>

#include "FuzzedDataProvider.h"
#include "log.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    glb_log_info(str.c_str());

    return 0;
}