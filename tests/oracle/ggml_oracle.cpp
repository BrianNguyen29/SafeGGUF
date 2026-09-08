#include "ggml.h"
#include "gguf.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char ** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <--version | --dump-types | --no-load <file> | --load-data <file>>\n", argv[0]);
        return 64;
    }

    if (strcmp(argv[1], "--version") == 0) {
        printf("ggml_version: %s\nggml_commit: %s\n", ggml_version(), ggml_commit());
        return 0;
    }

    if (strcmp(argv[1], "--dump-types") == 0) {
        printf("TYPE_TRAITS_BEGIN\n");
        for (int t = 0; t < GGML_TYPE_COUNT; t++) {
            const char * name = ggml_type_name((enum ggml_type)t);
            size_t bs = ggml_blck_size((enum ggml_type)t);
            size_t ts = ggml_type_size((enum ggml_type)t);
            printf("%d,%s,%zu,%zu\n", t, name ? name : "NULL", bs, ts);
        }
        printf("TYPE_TRAITS_END\n");
        return 0;
    }

    if (argc < 3) {
        fprintf(stderr, "Missing file path\n");
        return 64;
    }

    const char * mode = argv[1];
    const char * path = argv[2];
    bool load_data = (strcmp(mode, "--load-data") == 0);

    struct ggml_context * ctx = NULL;
    struct gguf_init_params params;
    params.no_alloc = !load_data;
    params.ctx = load_data ? &ctx : NULL;

    struct gguf_context * gctx = gguf_init_from_file(path, params);
    if (!gctx) {
        printf("REJECT\n");
        return 2;
    }
    gguf_free(gctx);
    if (ctx) {
        ggml_free(ctx);
    }
    printf("PASS\n");
    return 0;
}
