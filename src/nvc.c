/*
 * Copyright (c) 2017-2018, NVIDIA CORPORATION. All rights reserved.
 */

#include <gnu/lib-names.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "nvc_internal.h"

#include "common.h"
#include "driver.h"
#include "dxcore.h"
#include "debug.h"
#include "error.h"
#ifdef WITH_NVCGO
#include "nvcgo.h"
#endif
#include "options.h"
#include "utils.h"
#include "xfuncs.h"

static int copy_config(struct error *, struct nvc_context *, const struct nvc_config *);

const char interpreter[] __attribute__((section(".interp"))) = LIB_DIR "/" LD_SO;

const struct __attribute__((__packed__)) {
        Elf64_Nhdr hdr;
        uint32_t desc[5];
} abitag __attribute__((section (".note.ABI-tag"))) = {
        {0x04, 0x10, 0x01},
        {0x554e47, 0x0, 0x3, 0xa, 0x0}, /* GNU Linux 3.10.0 */
};

static const struct nvc_version version = {
        NVC_MAJOR,
        NVC_MINOR,
        NVC_PATCH,
        NVC_VERSION,
};

void
nvc_entrypoint(void)
{
        printf("version: %s\n", NVC_VERSION);
        printf("build date: %s\n", BUILD_DATE);
        printf("build revision: %s\n", BUILD_REVISION);
        printf("build compiler: %s\n", BUILD_COMPILER);
        printf("build platform: %s\n", BUILD_PLATFORM);
        printf("build flags: %s\n", BUILD_FLAGS);
        exit(EXIT_SUCCESS);
}

const struct nvc_version *
nvc_version(void)
{
        return (&version);
}

struct nvc_config *
nvc_config_new(void)
{
        struct nvc_config *cfg;

        if ((cfg = calloc(1, sizeof(*cfg))) == NULL)
                return (NULL);
        cfg->uid = (uid_t)-1;
        cfg->gid = (gid_t)-1;
        return (cfg);
}

void
nvc_config_free(struct nvc_config *cfg)
{
        if (cfg == NULL)
                return;
        free(cfg);
}

struct nvc_context *
nvc_context_new(void)
{
        struct nvc_context *ctx;

        if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
                return (NULL);
        return (ctx);
}

void
nvc_context_free(struct nvc_context *ctx)
{
        if (ctx == NULL)
                return;
        error_reset(&ctx->err);
        free(ctx);
}

static int
copy_config(struct error *err, struct nvc_context *ctx, const struct nvc_config *cfg)
{
        const char *root, *ldcache;
        uint32_t uid, gid;

        root = (cfg->root != NULL) ? cfg->root : "/";
        if ((ctx->cfg.root = xstrdup(err, root)) == NULL)
                return (-1);

        ldcache = (cfg->ldcache != NULL) ? cfg->ldcache : LDCACHE_PATH;
        if ((ctx->cfg.ldcache = xstrdup(err, ldcache)) == NULL)
                return (-1);

        if (cfg->uid != (uid_t)-1)
                ctx->cfg.uid = cfg->uid;
        else {
                if (file_read_uint32(err, PROC_OVERFLOW_UID, &uid) < 0)
                        return (-1);
                ctx->cfg.uid = (uid_t)uid;
        }
        if (cfg->gid != (gid_t)-1)
                ctx->cfg.gid = cfg->gid;
        else {
                if (file_read_uint32(err, PROC_OVERFLOW_GID, &gid) < 0)
                        return (-1);
                ctx->cfg.gid = (gid_t)gid;
        }

        ctx->cfg.cxpu_enable = cfg->cxpu_enable;
        ctx->cfg.cxpu_container_mem_limit = cfg->cxpu_container_mem_limit;
        strncpy(ctx->cfg.cxpu_instance_id, cfg->cxpu_instance_id, CXPU_MAX_INSTANCE_ID_LEN);

        log_infof("using root %s", ctx->cfg.root);
        log_infof("using ldcache %s", ctx->cfg.ldcache);
        log_infof("using unprivileged user %"PRIu32":%"PRIu32, (uint32_t)ctx->cfg.uid, (uint32_t)ctx->cfg.gid);
        return (0);
}

int
nvc_init(struct nvc_context *ctx, const struct nvc_config *cfg, const char *opts)
{
        int32_t flags;
        char path[PATH_MAX];

        if (ctx == NULL)
                return (-1);
        if (ctx->initialized)
                return (0);
        if (cfg == NULL)
                cfg = &(struct nvc_config){NULL, NULL, (uid_t)-1, (gid_t)-1, false, {0}, ~0ull, 1};
        if (validate_args(ctx, !str_empty(cfg->ldcache) && !str_empty(cfg->root)) < 0)
                return (-1);
        if (opts == NULL)
                opts = default_library_opts;
        if ((flags = options_parse(&ctx->err, opts, library_opts, nitems(library_opts))) < 0)
                return (-1);

        log_open(secure_getenv("NVC_DEBUG_FILE"));
        log_infof("initializing library context (version=%s, build=%s)", NVC_VERSION, BUILD_REVISION);

        memset(&ctx->cfg, 0, sizeof(ctx->cfg));
        ctx->mnt_ns = -1;

        if (copy_config(&ctx->err, ctx, cfg) < 0)
                goto fail;
        if (xsnprintf(&ctx->err, path, sizeof(path), PROC_NS_PATH(PROC_SELF), "mnt") < 0)
                goto fail;
        if ((ctx->mnt_ns = xopen(&ctx->err, path, O_RDONLY|O_CLOEXEC)) < 0)
                goto fail;

        // Initialize dxcore first to check if we are on a platform that supports dxcore.
        // If we are on not a platform with dxcore we will load the nvidia kernel modules and
        // use the nvidia libraries directly. If we do have access to dxcore, we will
        // do all the initial setup using dxcore and piggy back on the dxcore infrastructure
        // to enumerate gpus and find the driver location
        log_info("attempting to load dxcore to see if we are running under Windows Subsystem for Linux (WSL)");
        if (dxcore_init_context(&ctx->dxcore) < 0) {
                log_info("dxcore initialization failed, continuing assuming a non-WSL environment");
                ctx->dxcore.initialized = 0;
        } else if (ctx->dxcore.adapterCount == 0) {
                log_err("dxcore initialization succeeded but no adapters were found");
                error_setx(&ctx->err, "WSL environment detected but no adapters were found");
                goto fail;
        }

        if (driver_init(&ctx->err, &ctx->dxcore, ctx->cfg.root, ctx->cfg.uid, ctx->cfg.gid) < 0)
                goto fail;

        #ifdef WITH_NVCGO
        if (nvcgo_init(&ctx->err) < 0)
                goto fail;
        #endif

        ctx->initialized = true;
        return (0);

 fail:
        free(ctx->cfg.root);
        free(ctx->cfg.ldcache);
        xclose(ctx->mnt_ns);
        return (-1);
}

int
nvc_shutdown(struct nvc_context *ctx)
{
        if (ctx == NULL)
                return (-1);

        log_info("shutting down library context");

        int rv = 0;
        #ifdef WITH_NVCGO
        if (nvcgo_shutdown(&ctx->err) < 0) {
                log_warnf("error shutting down nvcgo rpc service: %s", ctx->err.msg);
                rv = -1;
        }
        #endif
        if (driver_shutdown(&ctx->err) < 0) {
                log_warnf("error shutting down driver rpc service: %s", ctx->err.msg);
                rv = -1;
        }

        if (!ctx->initialized)
                return (rv);

        if (ctx->dxcore.initialized)
                dxcore_deinit_context(&ctx->dxcore);

        free(ctx->cfg.root);
        free(ctx->cfg.ldcache);
        xclose(ctx->mnt_ns);

        memset(&ctx->cfg, 0, sizeof(ctx->cfg));
        ctx->mnt_ns = -1;

        log_close();
        ctx->initialized = false;
        return (rv);
}

const char *
nvc_error(struct nvc_context *ctx)
{
        if (ctx == NULL)
                return (NULL);
        if (ctx->err.code != 0 && ctx->err.msg == NULL)
                return ("unknown error");
        return (ctx->err.msg);
}
