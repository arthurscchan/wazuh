#define _GNU_SOURCE
/* Fuzzer for the wazuh version-parsing helpers (shared/src/version_op.c).
 *
 * Threat model:
 * - compare_wazuh_versions() decides upgrade/compatibility decisions from
 *   version strings that originate from agents and package metadata (both
 *   untrusted in a manager/agent fleet), get_release_from_build() and
 *   win_processor_arch_to_machine() map untrusted Windows build/arch
 *   identifiers reported by agents, and OSX_ReleaseName() maps attacker-
 *   checkable Darwin kernel versions reported by endpoints.
 * - A real finding is a memory-safety violation in the parsers, or a
 *   comparison/logic defect that mis-orders versions (drive with adjacent
 *   and malformed versions to keep the ordering logic honest).
 *
 * Harness contract (legitimate input): all entry points take C strings.
 * Input layout: <ver1> NUL <ver2> NUL <build> NUL <arch> NUL <4 flag bytes>.
 * The last four bytes drive compare_patch and the OSX_ReleaseName version.
 * The one heap returner (get_release_from_build) is freed; the other two
 * helpers return static storage and are intentionally not freed.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "version_op.h"

#define FZ_MAX_INPUT (8u * 1024u)

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 8 || size > FZ_MAX_INPUT) {
        return 0;
    }

    const uint8_t *field[4];
    size_t len[4];
    const uint8_t *cursor = data;
    size_t remaining = size - 4u;
    for (int i = 0; i < 4; i++) {
        field[i] = cursor;
        const uint8_t *nul = memchr(cursor, '\0', remaining);
        if (nul == NULL) {
            return 0;
        }
        len[i] = (size_t) (nul - cursor);
        remaining -= len[i] + 1u;
        cursor = nul + 1;
    }

    char *v1 = strndup((const char *) field[0], len[0]);
    char *v2 = strndup((const char *) field[1], len[1]);
    char *arch = strndup((const char *) field[3], len[3]);
    if (v1 == NULL || v2 == NULL || arch == NULL) {
        free(v1);
        free(v2);
        free(arch);
        return 0;
    }

    uint32_t flags = (uint32_t) data[size - 4] |
                     ((uint32_t) data[size - 3] << 8) |
                     ((uint32_t) data[size - 2] << 16) |
                     ((uint32_t) data[size - 1] << 24);

    (void) compare_wazuh_versions(v1, v2, flags & 1u);

    /* get_release_from_build() and OSX_ReleaseName() are inside the
       #ifdef WIN32 section of version_op.c and do not exist in Linux
       agent builds; only the two symbols below are reachable here. */
    (void) win_processor_arch_to_machine(arch);

    free(v1);
    free(v2);
    free(arch);
    return 0;
}
