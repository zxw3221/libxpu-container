/*
 * Copyright (c) 2017-2018, NVIDIA CORPORATION. All rights reserved.
 */

#include <sys/sysmacros.h>

#include <errno.h>
#include <limits.h>
#include <nvidia-modprobe-utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nvc_internal.h"

#include "driver.h"
#include "elftool.h"
#include "error.h"
#include "ldcache.h"
#include "options.h"
#include "utils.h"
#include "xfuncs.h"

#define MAX_BINS (nitems(utility_bins) + \
                  nitems(compute_bins))
#define MAX_LIBS (nitems(dxcore_libs) + \
                  nitems(ngx_libs) + \
                  nitems(utility_libs) + \
                  nitems(compute_libs) + \
                  nitems(video_libs) + \
                  nitems(graphics_libs) + \
                  nitems(graphics_libs_glvnd) + \
                  nitems(graphics_libs_compat))

static int select_libraries(struct error *, void *, const char *, const char *, const char *);
static int select_wsl_libraries(struct error *, void *, const char *, const char *, const char *);
static int find_library_paths(struct error *, struct dxcore_context *, struct nvc_driver_info *, const char *, const char *, const char * const [], size_t);
static int find_binary_paths(struct error *, struct dxcore_context*, struct nvc_driver_info *, const char *, const char * const [], size_t);
static int find_device_node(struct error *, const char *, const char *, struct nvc_device_node *);
static int find_path(struct error *, const char *, const char *, const char *, char **);
static int lookup_paths(struct error *, struct dxcore_context *, struct nvc_driver_info *, const char *, int32_t, const char *);
static int lookup_libraries(struct error *, struct dxcore_context *, struct nvc_driver_info *, const char *, int32_t, const char *);
static int lookup_binaries(struct error *, struct dxcore_context *, struct nvc_driver_info *, const char *, int32_t);
static int lookup_firmwares(struct error *, struct dxcore_context *, struct nvc_driver_info *, const char *, int32_t);
static int lookup_devices(struct error *, struct dxcore_context *, struct nvc_driver_info *, const char *, int32_t);
static int lookup_ipcs(struct error *, struct nvc_driver_info *, const char *, int32_t);
static int fill_mig_device_info(struct nvc_context *, bool mig_enabled, struct driver_device *, struct nvc_device *);
static void clear_mig_device_info(struct nvc_mig_device_info *);

/*
 * Display libraries are not needed.
 *
 * "libnvidia-gtk2.so" // GTK2 (used by nvidia-settings)
 * "libnvidia-gtk3.so" // GTK3 (used by nvidia-settings)
 * "libnvidia-wfb.so"  // Wrapped software rendering module for X server
 * "nvidia_drv.so"     // Driver module for X server
 * "libglx.so"         // GLX extension module for X server
 */

static const char * const utility_bins[] = {
        "xpu_smi",                          /* System management interface */
};

static const char * const compute_bins[] = {
        "nvidia-cuda-mps-control",          /* Multi process service CLI */
        "nvidia-cuda-mps-server",           /* Multi process service server */
};

static const char * const utility_libs[] = {
        "libxpuml.so.1",                      /* Management library */
        "libxpurt.so",                      /* Management library */
};

static const char * const compute_libs[] = {
        "libcuda.so",                       /* CUDA driver library */
};

static const char * const video_libs[] = {
};

static const char * const graphics_libs[] = {
};

static const char * const graphics_libs_glvnd[] = {
};

static const char * const graphics_libs_compat[] = {
};

static const char * const ngx_libs[] = {
};

static const char * const dxcore_libs[] = {
};

static int
select_libraries(struct error *err, void *ptr, const char *root, const char *orig_path, const char *alt_path)
{
        char path[PATH_MAX];
        struct nvc_driver_info *info = ptr;
        struct elftool et;
        char *lib;
        int rv = true;

        if (path_join(err, path, root, alt_path) < 0)
                return (-1);
        elftool_init(&et, err);
        if (elftool_open(&et, path) < 0)
                return (-1);

        lib = basename(alt_path);
        if (str_has_prefix(lib, "libnvidia-tls.so")) {
                /* Only choose the TLS library using the new ABI (kernel 2.3.99). */
                if ((rv = elftool_has_abi(&et, (uint32_t[3]){0x02, 0x03, 0x63})) != true)
                        goto done;
        }
        /* Check the driver version. */
        if ((rv = str_has_suffix(lib, info->nvrm_version)) == false)
                goto done;
        if (str_array_match_prefix(lib, graphics_libs_compat, nitems(graphics_libs_compat))) {
                /* Only choose OpenGL/EGL libraries issued by NVIDIA. */
                if ((rv = elftool_has_dependency(&et, "libnvidia-glcore.so")) != false)
                        goto done;
                if ((rv = elftool_has_dependency(&et, "libnvidia-eglcore.so")) != false)
                        goto done;
        }

 done:
        if (rv)
                log_infof((orig_path == NULL) ? "%s %s" : "%s %s over %s", "selecting", alt_path, orig_path);
        else
                log_infof("skipping %s", alt_path);

        elftool_close(&et);
        return (rv);
}

static int
select_wsl_libraries(struct error *err, void *ptr, const char *root, const char *orig_path, const char *alt_path)
{
        int rv = true;

        // Unused parameters
        err = err;
        ptr = ptr;
        root = root;

        // Always prefer the lxss libraries
        if (orig_path && strstr(orig_path, "/wsl/lib/")) {
                rv = false;
                goto done;
        }

 done:
        if (rv)
                log_infof((orig_path == NULL) ? "%s %s" : "%s %s over %s", "selecting", alt_path, orig_path);
        else
                log_infof("skipping %s", alt_path);
        return (rv);
}

static int
find_library_paths(struct error *err, struct dxcore_context *dxcore, struct nvc_driver_info *info,
                   const char *root, const char *ldcache, const char * const libs[], size_t size)
{
        char path[PATH_MAX];
        struct ldcache ld;
        int rv = -1;

        ldcache_select_fn select_libraries_fn = dxcore->initialized ? select_wsl_libraries : select_libraries;

        if (path_resolve_full(err, path, root, ldcache) < 0)
                return (-1);
        ldcache_init(&ld, err, path);
        if (ldcache_open(&ld) < 0)
                return (-1);

        info->nlibs = size;
        info->libs = array_new(err, size);
        if (info->libs == NULL)
                goto fail;
        if (ldcache_resolve(&ld, LIB_ARCH, root, libs,
            info->libs, info->nlibs, select_libraries_fn, info) < 0)
                goto fail;

        info->nlibs32 = size;
        info->libs32 = array_new(err, size);
        if (info->libs32 == NULL)
                goto fail;
        if (ldcache_resolve(&ld, LIB32_ARCH, root, libs,
            info->libs32, info->nlibs32, select_libraries_fn, info) < 0)
                goto fail;
        rv = 0;

 fail:
        if (ldcache_close(&ld) < 0)
                return (-1);
        return (rv);
}

static int
find_binary_paths(struct error *err, struct dxcore_context* dxcore, struct nvc_driver_info* info,
                  const char *root, const char * const bins[], size_t size)
{
        char *env, *ptr;
        const char *dir;
        char tmp[PATH_MAX];
        char path[PATH_MAX];
        int rv = -1;

        if ((env = secure_getenv("PATH")) == NULL) {
                error_setx(err, "environment variable PATH not found");
                return (-1);
        }
        if ((env = ptr = xstrdup(err, env)) == NULL)
                return (-1);

        info->nbins = size;
        info->bins = array_new(err, size);
        if (info->bins == NULL)
                goto fail;

        // If we are on WSL we want to check if we have a copy of this
        // binary in our driver store first
        if (dxcore->initialized) {
                for (size_t i = 0; i < size; ++i) {
                        for (unsigned int adapterIndex = 0; adapterIndex < dxcore->adapterCount; adapterIndex++) {
                                if (path_join(NULL, tmp, dxcore->adapterList[adapterIndex].pDriverStorePath, bins[i]) < 0)
                                        continue;
                                if (path_resolve(NULL, path, root, tmp) < 0)
                                        continue;
                                if (file_exists_at(NULL, root, path) == true) {
                                        info->bins[i] = xstrdup(err, path);
                                        if (info->bins[i] == NULL)
                                                goto fail;
                                        log_infof("selecting %s", path);
                                }
                        }
                }
        }

        while ((dir = strsep(&ptr, ":")) != NULL) {
                if (*dir == '\0')
                        dir = ".";
                for (size_t i = 0; i < size; ++i) {
                        if (info->bins[i] != NULL)
                                continue;
                        if (path_join(NULL, tmp, dir, bins[i]) < 0)
                                continue;
                        if (path_resolve(NULL, path, root, tmp) < 0)
                                continue;
                        if (file_exists_at(NULL, root, path) == true) {
                                info->bins[i] = xstrdup(err, path);
                                if (info->bins[i] == NULL)
                                        goto fail;
                                log_infof("selecting %s", path);
                        }
                }
        }
        rv = 0;

 fail:
        free(env);
        return (rv);
}

static int
find_device_node(struct error *err, const char *root, const char *dev, struct nvc_device_node *node)
{
        char path[PATH_MAX];
        struct stat s;

        if (path_resolve_full(err, path, root, dev) < 0)
                return (-1);
        if (xstat(err, path, &s) == 0) {
                *node = (struct nvc_device_node){(char *)dev, s.st_rdev};
                return (true);
        }
        if (err->code == ENOENT) {
                log_warnf("missing device %s", dev);
                return (false);
        }
        return (-1);
}

// find_path resolves a path relative to the specified root. If the path exists, the
// output buffer is populated with the resolved path not including the root. A `tag` parameter is
// provided to control logging output.
static int
find_path(struct error *err, const char *tag, const char *root, const char *target, char **buf)
{
        char path[PATH_MAX];
        int ret;

        if (path_resolve(err, path, root, target) < 0)
                return (-1);
        if ((ret = file_exists_at(err, root, path)) < 0)
                return (-1);
        if (ret) {
                log_infof("listing %s path %s", tag, path);
                if ((*buf = xstrdup(err, path)) == NULL) {
                        log_err("error creating output buffer");
                        return (-1);
                }
        } else {
                log_warnf("missing %s path %s", tag, target);
        }
        return (0);
}

static int
lookup_paths(struct error *err, struct dxcore_context *dxcore, struct nvc_driver_info *info, const char *root, int32_t flags, const char *ldcache)
{
        if (lookup_libraries(err, dxcore, info, root, flags, ldcache) < 0) {
                log_err("error looking up libraries");
                return (-1);
        }

        if (lookup_binaries(err, dxcore, info, root, flags) < 0) {
                log_err("error looking up binaries");
                return (-1);
        }

        if (lookup_firmwares(err, dxcore, info, root, flags) < 0) {
                log_err("error looking up additional paths");
                return (-1);
        }

        return (0);
}

static int
lookup_libraries(struct error *err, struct dxcore_context *dxcore, struct nvc_driver_info *info, const char *root, int32_t flags, const char *ldcache)
{
        const char *libs[MAX_LIBS];
        const char **ptr = libs;

        ptr = array_append(ptr, utility_libs, nitems(utility_libs));
        ptr = array_append(ptr, compute_libs, nitems(compute_libs));
        ptr = array_append(ptr, ngx_libs, nitems(ngx_libs));
        ptr = array_append(ptr, video_libs, nitems(video_libs));
        ptr = array_append(ptr, graphics_libs, nitems(graphics_libs));
        if (flags & OPT_NO_GLVND)
                ptr = array_append(ptr, graphics_libs_compat, nitems(graphics_libs_compat));
        else
                ptr = array_append(ptr, graphics_libs_glvnd, nitems(graphics_libs_glvnd));

        if (dxcore->initialized)
                ptr = array_append(ptr, dxcore_libs, nitems(dxcore_libs));

        if (find_library_paths(err, dxcore, info, root, ldcache, libs, (size_t)(ptr - libs)) < 0)
                return (-1);

        for (size_t i = 0; info->libs != NULL && i < info->nlibs; ++i) {
                if (info->libs[i] == NULL)
                        log_warnf("missing library %s", libs[i]);
        }
        for (size_t i = 0; info->libs32 != NULL && i < info->nlibs32; ++i) {
                if (info->libs32[i] == NULL)
                        log_warnf("missing compat32 library %s", libs[i]);
        }
        array_pack(info->libs, &info->nlibs);
        array_pack(info->libs32, &info->nlibs32);
        return (0);
}

static int
lookup_binaries(struct error *err, struct dxcore_context* dxcore, struct nvc_driver_info *info, const char *root, int32_t flags)
{
        const char *bins[MAX_BINS];
        const char **ptr = bins;

        ptr = array_append(ptr, utility_bins, nitems(utility_bins));
        if (!(flags & OPT_NO_MPS))
                ptr = array_append(ptr, compute_bins, nitems(compute_bins));

        if (find_binary_paths(err, dxcore, info, root, bins, (size_t)(ptr - bins)) < 0)
                return (-1);

        for (size_t i = 0; info->bins != NULL && i < info->nbins; ++i) {
                if (info->bins[i] == NULL)
                        log_warnf("missing binary %s", bins[i]);
        }
        array_pack(info->bins, &info->nbins);
        return (0);
}

static int
lookup_firmwares(struct error *err, struct dxcore_context *dxcore, struct nvc_driver_info *info, const char *root, int32_t flags) {
        (void)flags;
        char **ptr;
        int rc = -1;

        char *firmware_path = NULL;
        char *resolved_path = NULL;

        if (dxcore->initialized) {
                log_info("skipping path lookup for dxcore");
                return 0;
        }

        // If the NVIDIA driver firmware path exists, include this in the mounted folders.
        if (xasprintf(err, &firmware_path, NV_FIRMWARE_DRIVER_PATH, info->nvrm_version) < 0) {
                log_errf("error constructing firmware path for %s", info->nvrm_version);
                return (-1);
        }
        if (find_path(err, "firmware", root, firmware_path, &resolved_path) < 0) {
                log_errf("error finding firmware path %s", firmware_path);
                goto cleanup;
        }
        if (resolved_path == NULL) {
                rc = 0;
                goto cleanup;
        }

        info->nfirmwares = 1;
        info->firmwares = ptr = array_new(err, info->nfirmwares);
        if (info->firmwares == NULL) {
                log_err("error creating path array");
                goto cleanup;
        }
        info->firmwares[0] = firmware_path;
        return (0);

cleanup:
        free(firmware_path);
        return (rc);
}

static int
lookup_devices(struct error *err, struct dxcore_context *dxcore, struct nvc_driver_info *info, const char *root, int32_t flags)
{
        struct nvc_device_node uvm, uvm_tools, modeset, nvidiactl, dxg, *node;
        int has_dxg = 0;
        int has_nvidiactl = 0;
        int has_uvm = 0;
        int has_uvm_tools = 0;
        int has_modeset = 0;

        if (dxcore->initialized) {
                struct stat dxgDeviceStat;

                if (xstat(err, (char *)MSFT_DXG_DEVICE_PATH, &dxgDeviceStat) < 0) {
                        log_errf("failed to query device information for %s", MSFT_DXG_DEVICE_PATH);
                        return (-1);
                }

                dxg.path = (char *)MSFT_DXG_DEVICE_PATH;
                dxg.id = dxgDeviceStat.st_rdev;
                has_dxg = 1;
        }
        else {
                if (!(flags & OPT_NO_UVM)) {
                        if ((has_uvm = find_device_node(err, root, NV_UVM_DEVICE_PATH, &uvm)) < 0)
                                return (-1);
                        if ((has_uvm_tools = find_device_node(err, root, NV_UVM_TOOLS_DEVICE_PATH, &uvm_tools)) < 0)
                                return (-1);
                }
                if (!(flags & OPT_NO_MODESET)) {
                        modeset.path = (char *)NV_MODESET_DEVICE_PATH;
                        modeset.id = makedev(NV_DEVICE_MAJOR, NV_MODESET_DEVICE_MINOR);
                        has_modeset = 1;
                }
                nvidiactl.path = (char *)NV_CTL_DEVICE_PATH;
                struct stat dev_stat;
                stat(NV_CTL_DEVICE_PATH, &dev_stat);
                nvidiactl.id = dev_stat.st_rdev;
                has_nvidiactl = 1;
        }

        info->ndevs = (size_t)(has_dxg + has_nvidiactl + has_uvm + has_uvm_tools + has_modeset);
        info->devs = node = xcalloc(err, info->ndevs, sizeof(*info->devs));
        if (info->devs == NULL)
                return (-1);

        if (has_dxg)
                *(node++) = dxg;
        if (has_nvidiactl)
                *(node++) = nvidiactl;
        if (has_uvm)
                *(node++) = uvm;
        if (has_uvm_tools)
                *(node++) = uvm_tools;
        if (has_modeset)
                *(node++) = modeset;

        for (size_t i = 0; i < info->ndevs; ++i)
                log_infof("listing device %s", info->devs[i].path);
        return (0);
}

static int
lookup_ipcs(struct error *err, struct nvc_driver_info *info, const char *root, int32_t flags)
{
        char **ptr;
        const char *mps;

        info->nipcs = 3;
        info->ipcs = ptr = array_new(err, info->nipcs);
        if (info->ipcs == NULL)
                return (-1);

        if (!(flags & OPT_NO_PERSISTENCED)) {
                if (find_path(err, "ipc", root, NV_PERSISTENCED_SOCKET, ptr++) < 0)
                        return (-1);
        }
        if (!(flags & OPT_NO_FABRICMANAGER)) {
                if (find_path(err, "ipc", root, NV_FABRICMANAGER_SOCKET, ptr++) < 0)
                        return (-1);
        }
        if (!(flags & OPT_NO_MPS)) {
                if ((mps = secure_getenv("CUDA_MPS_PIPE_DIRECTORY")) == NULL)
                        mps = NV_MPS_PIPE_DIR;
                if (find_path(err, "ipc", root, mps, ptr++) < 0)
                        return (-1);
        }
        array_pack(info->ipcs, &info->nipcs);
        return (0);
}

static int
config_cxpus(struct nvc_context *ctx, int cxpu_count)
{
    struct driver_device *dev;
    struct error *err = &ctx->err;
    int i;

    for (i = 0; i < cxpu_count; i++) {
        if (driver_get_device(err, i, &dev) < 0)
            goto fail;

        if (ctx->cfg.cxpu_enable) {
            driver_create_device_cxpu(err, dev, ctx->cfg.cxpu_user_id);
            driver_set_device_memory_limit(err, dev, ctx->cfg.cxpu_user_id, 0,
                    ctx->cfg.cxpu_mem_limit_inbytes / cxpu_count);
        } else {
            driver_destroy_device_cxpu(err, dev, ctx->cfg.cxpu_user_id);
        }
    }

    fail:
        return (-1);
}

static int
init_nvc_device(struct nvc_context *ctx, unsigned int index, struct nvc_device *gpu)
{
        struct driver_device *dev;
        struct error *err = &ctx->err;
        bool mig_enabled;
        unsigned int minor;

        if (driver_get_device(err, index, &dev) < 0)
                goto fail;
        if (driver_get_device_model(err, dev, &gpu->model) < 0)
                goto fail;
        if (driver_get_device_uuid(err, dev, &gpu->uuid) < 0)
                goto fail;
        if (driver_get_device_busid(err, dev, &gpu->busid) < 0)
                goto fail;
        if (driver_get_device_arch(err, dev, &gpu->arch) < 0)
                goto fail;
        if (driver_get_device_brand(err, dev, &gpu->brand) < 0)
                goto fail;
        if (ctx->dxcore.initialized)
        {
                // No Device associated to a WSL GPU. Everything uses /dev/dxg
                gpu->node.path = NULL;
                minor = 0;

                // No MIG support for WSL
                gpu->mig_capable = 0;
                gpu->mig_caps_path = NULL;
                gpu->mig_devices.ndevices = 0;
                gpu->mig_devices.devices = NULL;

                log_infof("listing dxcore adapter %d (%s at %s)", index, gpu->uuid, gpu->busid);
        }
        else
        {

                gpu->mig_capable = 0;
                gpu->mig_caps_path = NULL;
                gpu->mig_devices.ndevices = 0;
                gpu->mig_devices.devices = NULL;

                if (driver_get_device_minor(err, dev, &minor) < 0)
                        goto fail;
#if 0
                if (xasprintf(err, &gpu->mig_caps_path, NV_GPU_CAPS_PATH, minor) < 0)
                        goto fail;
#endif
                if (xasprintf(err, &gpu->node.path, NV_DEVICE_PATH, index) < 0)
                        goto fail;
                 struct stat dev_stat;
                stat(gpu->node.path, &dev_stat);
                gpu->node.id = dev_stat.st_rdev;
                log_infof("listing device %s (%s at %s)", gpu->node.path, gpu->uuid, gpu->busid);
        }

        return 0;

 fail:
        return (-1);
}


bool
match_binary_flags(const char *bin, int32_t flags)
{
        if ((flags & OPT_UTILITY_BINS) && str_array_match_prefix(bin, utility_bins, nitems(utility_bins)))
                return (true);
        if ((flags & OPT_COMPUTE_BINS) && str_array_match_prefix(bin, compute_bins, nitems(compute_bins)))
                return (true);
        return (false);
}

bool
match_library_flags(const char *lib, int32_t flags)
{
        if (str_array_match_prefix(lib, dxcore_libs, nitems(dxcore_libs)))
                return (true);
        if ((flags & OPT_UTILITY_LIBS) && str_array_match_prefix(lib, utility_libs, nitems(utility_libs)))
                return (true);
        if ((flags & OPT_COMPUTE_LIBS) && str_array_match_prefix(lib, compute_libs, nitems(compute_libs)))
                return (true);
        if ((flags & OPT_VIDEO_LIBS) && str_array_match_prefix(lib, video_libs, nitems(video_libs)))
                return (true);
        if ((flags & OPT_GRAPHICS_LIBS) && (str_array_match_prefix(lib, graphics_libs, nitems(graphics_libs)) ||
            str_array_match_prefix(lib, graphics_libs_glvnd, nitems(graphics_libs_glvnd)) ||
            str_array_match_prefix(lib, graphics_libs_compat, nitems(graphics_libs_compat))))
                return (true);
        if ((flags & OPT_NGX_LIBS) && str_array_match_prefix(lib, ngx_libs, nitems(ngx_libs)))
                return (true);
        return (false);
}

struct nvc_driver_info *
nvc_driver_info_new(struct nvc_context *ctx, const char *opts)
{
        struct nvc_driver_info *info;
        int32_t flags;

        if (validate_context(ctx) < 0)
                return (NULL);
        if (opts == NULL)
                opts = default_driver_opts;
        if ((flags = options_parse(&ctx->err, opts, driver_opts, nitems(driver_opts))) < 0)
                return (NULL);

        log_infof("requesting driver information with '%s'", opts);
        if ((info = xcalloc(&ctx->err, 1, sizeof(*info))) == NULL)
                return (NULL);

        if (driver_get_rm_version(&ctx->err, &info->nvrm_version) < 0)
                goto fail;
        if (driver_get_cuda_version(&ctx->err, &info->cuda_version) < 0)
                goto fail;
        if (lookup_paths(&ctx->err, &ctx->dxcore, info, ctx->cfg.root, flags, ctx->cfg.ldcache) < 0)
                goto fail;
        if (lookup_devices(&ctx->err, &ctx->dxcore, info, ctx->cfg.root, flags) < 0)
                goto fail;
        if (lookup_ipcs(&ctx->err, info, ctx->cfg.root, flags) < 0)
                goto fail;
        return (info);

 fail:
        nvc_driver_info_free(info);
        return (NULL);
}

void
nvc_driver_info_free(struct nvc_driver_info *info)
{
        if (info == NULL)
                return;
        free(info->nvrm_version);
        free(info->cuda_version);
        array_free(info->bins, info->nbins);
        array_free(info->libs, info->nlibs);
        array_free(info->libs32, info->nlibs32);
        array_free(info->ipcs, info->nipcs);
        array_free(info->firmwares, info->nfirmwares);
        free(info->devs);
        free(info);
}

struct nvc_device_info *
nvc_device_info_new(struct nvc_context *ctx, const char *opts)
{
        struct nvc_device_info *info;
        struct nvc_device *gpu;
        unsigned int n;
        int rv = -1;

        /*int32_t flags;*/

        if (validate_context(ctx) < 0)
                return (NULL);
        if (opts == NULL)
                opts = default_device_opts;
        /*
        if ((flags = options_parse(&ctx->err, opts, device_opts, nitems(device_opts))) < 0)
                return (NULL);
        */

        if ((info = xcalloc(&ctx->err, 1, sizeof(*info))) == NULL)
                return (NULL);

        if (driver_get_device_count(&ctx->err, &n) < 0)
            goto fail;

        info->ngpus = n;
        info->gpus = gpu = xcalloc(&ctx->err, info->ngpus, sizeof(*info->gpus));
        if (info->gpus == NULL)
                goto fail;

        config_cxpus(ctx, n);

        for (unsigned int i = 0; i < n; ++i, ++gpu) {
                rv = init_nvc_device(ctx, i, gpu);
                if (rv < 0) goto fail;
        }

        return (info);

 fail:
        nvc_device_info_free(info);
        return (NULL);
}

void
nvc_device_info_free(struct nvc_device_info *info)
{
        if (info == NULL)
                return;
        for (size_t i = 0; info->gpus != NULL && i < info->ngpus; ++i) {
                free(info->gpus[i].model);
                free(info->gpus[i].uuid);
                free(info->gpus[i].busid);
                free(info->gpus[i].arch);
                free(info->gpus[i].brand);
                free(info->gpus[i].node.path);
        }
        free(info->gpus);
        free(info);
}

int
nvc_nvcaps_style(void)
{
        if (nvidia_get_chardev_major(NV_CAPS_MODULE_NAME) >= 0)
                return NVC_NVCAPS_STYLE_DEV;
        if (file_exists(NULL, NV_PROC_DRIVER_CAPS) >= 0)
                return NVC_NVCAPS_STYLE_PROC;
        return NVC_NVCAPS_STYLE_NONE;
}

int
nvc_nvcaps_device_from_proc_path(struct nvc_context *ctx, const char *cap_path, struct nvc_device_node *node)
{
        char abs_cap_path[PATH_MAX];
        char dev_name[PATH_MAX];
        int major, minor;
        int rv = -1;

        if (path_join(&ctx->err, abs_cap_path, ctx->cfg.root, cap_path) < 0)
                goto fail;

        if (nvidia_cap_get_device_file_attrs(abs_cap_path, &major, &minor, dev_name) == 0) {
                error_set(&ctx->err, "unable to get cap device attributes: %s", cap_path);
                goto fail;
        }

        if ((node->path = xstrdup(&ctx->err, dev_name)) == NULL)
                goto fail;
        node->id = makedev((unsigned int)major, (unsigned int)minor);

        rv = 0;

fail:
        return (rv);
}
