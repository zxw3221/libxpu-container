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
                {"instance", 'i', "instance_id", 0, "cxpu instance id", -1},
                {"device", 'D', "phy_device_id", 0, "physical device id", -1},
                {"create", 'c', NULL, 0, "cxpu create instance", -1},
                {"destroy", 'd', NULL, 0, "cxpu destroy instance", -1},
                {"mmem", 'm', "memory_inbytes", 0, "cxpu set instance main memory limitation", -1},
                {"hmem", 'h', "memory_inbytes", 0, "cxpu set instance high speed memory limitation", -1},
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
        case 'D':
                if (str_join(&err, &ctx->devices, arg, ",") < 0)
                        goto fatal;
                break;
        case 'i':
                strncpy(ctx->cxpu_instance_id, arg, CXPU_MAX_INSTANCE_ID_LEN);
                break;
        case 'c':
                ctx->cxpu_enable = true;
                break;
        case 'd':
                ctx->cxpu_enable = false;
                break;
        case 'm':
                ctx->cxpu_container_mem_limit = (uint64_t)atoll(arg);
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
        if (!ctx->cxpu_container_mem_limit) {
            uint64_t mem_limit = XPUML_CXPU_MEM_UNLIMIT;
            const char *mem_limit_str = getenv("CXPU_CONTAINER_MEMORY_LIMIT");
            if (mem_limit_str) {
                mem_limit = (uint64_t)atoll(mem_limit_str);
            }
            nvc_cfg->cxpu_container_mem_limit = mem_limit;
        } else {
            nvc_cfg->cxpu_container_mem_limit = ctx->cxpu_container_mem_limit;
        }
        // if no resource limit have been set, disable the cxpu
        if (nvc_cfg->cxpu_container_mem_limit == XPUML_CXPU_MEM_UNLIMIT)
            nvc_cfg->cxpu_enable = false;
        strncpy(nvc_cfg->cxpu_instance_id, ctx->cxpu_instance_id, CXPU_MAX_INSTANCE_ID_LEN);
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

        struct devices devices = {0};
        /* Allocate space for selecting GPU devices and MIG devices */
        if (new_devices(&err, dev, &devices) < 0) {
            warn("memory allocation failed: %s", err.msg);
            goto fail;
        }

        /* Select the visible GPU devices. */
        if (dev->ngpus > 0) {
            if (select_devices(&err, ctx->devices, dev, &devices) < 0) {
                    warnx("device error: %s", err.msg);
                    goto fail;
            }
        }


        if (devices.ngpus > 0) {
            nvc->cfg.cxpu_container_mem_count = devices.ngpus;
        } else {
            nvc->cfg.cxpu_container_mem_count = 1;
        }

        if (!strcmp(ctx->devices, "all")) {
            for (size_t i = 0; i < devices.ngpus; ++i) {
                if (libnvc.cxpu_config(nvc, (unsigned int)i) < 0) {
                    goto fail;
                }
            }
        } else if (ctx->devices != NULL) {
            for (size_t i = 0; i < devices.ngpus; ++i) {
               if (devices.gpus[i]->node.path != NULL) {
                   unsigned int dev_idx;
                   sscanf(devices.gpus[i]->node.path, "/dev/xpu%u", &dev_idx);
                   if (libnvc.cxpu_config(nvc, dev_idx) < 0) {
                       goto fail;
                   }
               }
            }
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
