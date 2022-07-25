/*
 * Copyright (c) 2017-2018, NVIDIA CORPORATION. All rights reserved.
 */

#include <sys/sysmacros.h>

#include <alloca.h>
#include <err.h>
#include <stdio.h>

#include "cli.h"
#include "../xpuml.h"

static error_t cxpu_parser(int, char *, struct argp_state *);

const struct argp cxpu_usage = {
        (const struct argp_option[]){
                {NULL, 0, NULL, 0, "Options:", -1},
                {"userid", 'u', "userid", 0, "user id", -1},
                {"pid", 'p', "PID", 0, "Container PID", -1},
                {"device", 'd', "DEVICE ID", 0, "Device UUID(s) or index(es) to isolate", -1},
                {"command", 'c', "cxpu command", 0, "cxpu control command", -1},
                {0},
        },
        cxpu_parser,
        NULL,
        "cxpu controller",
        NULL,
        NULL,
        NULL,
};

static error_t
cxpu_parser(int key, maybe_unused char *arg, struct argp_state *state)
{
        struct context *ctx = state->input;
        struct error err = {0};

        switch (key) {
        case 'p':
                if (str_to_pid(&err, arg, &ctx->pid) < 0)
                        goto fatal;
                break;
        case 'd':
                if (str_join(&err, &ctx->devices, arg, ",") < 0)
                        goto fatal;
                break;
        case 'u':
                strncpy(ctx->cxpu_user_id, arg, CXPU_MAX_USER_ID_LEN);
                break;
        case 'c':
                if (strncmp("create", arg, 6) == 0) {
                    ctx->cxpu_enable = true;
                    uint64_t mem_limit = XPUML_MEM_UNLIMIT;
                    const char *mem_limit_str = getenv("BAIDU_COM_XPU_MEM_LIMIT_INBYTES");
                    if (mem_limit_str) {
                        mem_limit = atoll(mem_limit_str);
                    }
                    ctx->cxpu_mem_limit_inbytes = mem_limit;
                } else {
                    ctx->cxpu_enable = false;
                }
                break;
        case ARGP_KEY_ARG:
                break;
        case ARGP_KEY_END:
                break;
        default:
                return (ARGP_ERR_UNKNOWN);
        }

        return (0);
 fatal:
        errx(EXIT_FAILURE, "input error: %s", err.msg);
        return (0);
}

int
cxpu_command(const struct context *ctx)
{
        bool run_as_root;
        struct nvc_context *nvc = NULL;
        struct nvc_config *nvc_cfg = NULL;
        struct nvc_driver_info *drv = NULL;
        struct nvc_device_info *dev = NULL;
        struct error err = {0};
        int rv = EXIT_FAILURE;

        run_as_root = (geteuid() == 0);
        if (run_as_root) {
                if (perm_set_capabilities(&err, CAP_PERMITTED, pcaps, nitems(pcaps)) < 0 ||
                    perm_set_capabilities(&err, CAP_INHERITABLE, NULL, 0) < 0 ||
                    perm_set_bounds(&err, bcaps, nitems(bcaps)) < 0) {
                        warnx("permission error: %s", err.msg);
                        return (rv);
                }
        }

        /* Initialize the library context. */
        if ((nvc = libnvc.context_new()) == NULL ||
            (nvc_cfg = libnvc.config_new()) == NULL) {
                warn("memory allocation failed");
                goto fail;
        }
        nvc_cfg->uid = (!run_as_root && ctx->uid == (uid_t)-1) ? geteuid() : ctx->uid;
        nvc_cfg->gid = (!run_as_root && ctx->gid == (gid_t)-1) ? getegid() : ctx->gid;
        nvc_cfg->root = ctx->root;
        nvc_cfg->ldcache = ctx->ldcache;
        nvc_cfg->cxpu_enable = ctx->cxpu_enable;
        strncpy(nvc_cfg->cxpu_user_id, ctx->cxpu_user_id, CXPU_MAX_USER_ID_LEN);
        nvc_cfg->cxpu_mem_limit_inbytes = ctx->cxpu_mem_limit_inbytes;
        if (libnvc.init(nvc, nvc_cfg, ctx->init_flags) < 0) {
                warnx("initialization error: %s", libnvc.error(nvc));
                goto fail;
        }

        /* Query the driver and device information. */
        if (run_as_root && perm_set_capabilities(&err, CAP_EFFECTIVE, ecaps[NVC_INFO], ecaps_size(NVC_INFO)) < 0) {
                warnx("permission error: %s", err.msg);
                goto fail;
        }
        if ((drv = libnvc.driver_info_new(nvc, NULL)) == NULL ||
            (dev = libnvc.device_info_new(nvc, NULL)) == NULL) {
                warnx("detection error: %s", libnvc.error(nvc));
                goto fail;
        }

        if (run_as_root && perm_set_capabilities(&err, CAP_EFFECTIVE, ecaps[NVC_SHUTDOWN], ecaps_size(NVC_SHUTDOWN)) < 0) {
                warnx("permission error: %s", err.msg);
                goto fail;
        }
        rv = EXIT_SUCCESS;
 fail:
        libnvc.shutdown(nvc);
        libnvc.device_info_free(dev);
        libnvc.driver_info_free(drv);
        libnvc.config_free(nvc_cfg);
        libnvc.context_free(nvc);
        error_reset(&err);
        return (rv);
}
