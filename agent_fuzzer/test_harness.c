// Test harness with branches that are easy to plateau on.
// The fuzzer will quickly find the shallow branches but get stuck
// on the deeper ones that require specific multi-byte magic values.
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Volatile to prevent optimizer from simplifying
volatile int sink;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    // Easy: fuzzer finds these quickly via havoc
    if (data[0] == 'A') {
        sink = 1;  // branch 1
        if (data[1] == 'B') {
            sink = 2;  // branch 2
        }
    }

    if (data[0] == 'X') {
        sink = 3;  // branch 3
    }

    // Hard plateau: needs a 4-byte magic that cmplog might partially help with,
    // but the deep nesting makes it very unlikely without guidance.
    // The agent should be able to read the source and guess "DEEP" + "SEED".
    if (size >= 8) {
        uint32_t magic1 = *(uint32_t *)(data);
        uint32_t magic2 = *(uint32_t *)(data + 4);
        // "DEEP" = 0x50454544 on little-endian
        if (magic1 == 0x50454544) {
            sink = 10;  // branch: needs "DEEP"
            // "SEED" = 0x44454553 on little-endian
            if (magic2 == 0x44454553) {
                sink = 20;  // branch: needs "DEEPSEED"
            }
        }
    }

    // Another hard path: needs specific checksum-like relationship
    if (size >= 6) {
        if (data[0] == 'C' && data[1] == 'K') {
            uint8_t sum = 0;
            for (int i = 2; i < 6; i++) sum += data[i];
            if (sum == 0xFF) {
                sink = 30;  // branch: needs CK + bytes summing to 0xFF
            }
        }
    }

    return 0;
}
