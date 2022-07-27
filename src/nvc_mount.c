/*
 * Copyright (c) 2017-2018, NVIDIA CORPORATION. All rights reserved.
 */

#include <sys/sysmacros.h>
#include <sys/mount.h>
#include <sys/types.h>

#include <errno.h>
#include <libgen.h>
#undef basename /* Use the GNU version of basename. */
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>

#include "nvc_internal.h"

#include "cgroup.h"
#include "error.h"
#include "options.h"
#include "utils.h"
#include "xfuncs.h"

static char **mount_files(struct error *, const char *, const struct nvc_container *, const char *, char *[], size_t);
static char **mount_driverstore_files(struct error *, const char *, const struct nvc_container *, const char *, const char *[], size_t);
static char *mount_directory(struct error *, const char *, const struct nvc_container *, const char *);
static char *mount_with_flags(struct error *, const char *, const char *,  uid_t, uid_t, unsigned long);
static char *mount_device(struct error *, const char *, const struct nvc_container *, const struct nvc_device_node *);
static void unmount(const char *);
static int  symlink_library(struct error *, const char *, const char *, const char *, uid_t, gid_t);
static int  symlink_libraries(struct error *, const struct nvc_container *, const char * const [], size_t);
static void filter_libraries(const struct nvc_driver_info *, char * [], size_t *);
static int  device_mount_dxcore(struct nvc_context *, const struct nvc_container *);
static int  device_mount_native(struct nvc_context *, const struct nvc_container *, const struct nvc_device *);

static char *
mount_directory(struct error *err, const char *root, const struct nvc_container *cnt, const char *dir)
{
        char src[PATH_MAX];
        char dst[PATH_MAX];
        if (path_join(err, src, root, dir) < 0)
                return (NULL);
        if (path_resolve_full(err, dst, cnt->cfg.rootfs, dir) < 0)
                return (NULL);
        return mount_with_flags(err, src, dst, cnt->uid, cnt->gid, MS_NOSUID|MS_RDONLY);
}

// mount_with_flags bind mounts the specified src to the the specified dst with the specified mount flags
static char *
mount_with_flags(struct error *err, const char *src, const char *dst, uid_t uid, uid_t gid, unsigned long mountflags) {
        mode_t mode;
        char *mnt;

        if (file_mode(err, src, &mode) < 0)
                goto fail;
        if (file_create(err, dst, NULL, uid, gid, mode) < 0)
                goto fail;

        log_infof("mounting %s at %s with flags 0x%lx", src, dst, mountflags);
        if (xmount(err, src, dst, NULL, MS_BIND, NULL) < 0)
                goto fail;
        if (xmount(err, NULL, dst, NULL, MS_BIND|MS_REMOUNT | mountflags, NULL) < 0)
                goto fail;
        if ((mnt = xstrdup(err, dst)) == NULL)
                goto fail;
        return (mnt);

 fail:
        unmount(mnt);
        return (NULL);
}

static char **
mount_files(struct error *err, const char *root, const struct nvc_container *cnt, const char *dir, char *paths[], size_t size)
{
        char src[PATH_MAX];
        char dst[PATH_MAX];
        mode_t mode;
        char *src_end, *dst_end, *file;
        char **mnt, **ptr;

        if (path_new(err, src, root) < 0)
                return (NULL);
        if (path_resolve_full(err, dst, cnt->cfg.rootfs, dir) < 0)
                return (NULL);
        if (file_create(err, dst, NULL, cnt->uid, cnt->gid, MODE_DIR(0755)) < 0)
                return (NULL);
        src_end = src + strlen(src);
        dst_end = dst + strlen(dst);

        mnt = ptr = array_new(err, size + 1); /* NULL terminated. */
        if (mnt == NULL)
                return (NULL);

        for (size_t i = 0; i < size; ++i) {
                file = basename(paths[i]);
                if (!match_binary_flags(file, cnt->flags) && !match_library_flags(file, cnt->flags))
                        continue;
                if (path_append(err, src, paths[i]) < 0)
                        goto fail;
                if (path_append(err, dst, file) < 0)
                        goto fail;
                if (file_mode(err, src, &mode) < 0)
                        goto fail;
                if (file_create(err, dst, NULL, cnt->uid, cnt->gid, mode) < 0)
                        goto fail;

                log_infof("mounting %s at %s", src, dst);
                if (xmount(err, src, dst, NULL, MS_BIND, NULL) < 0)
                        goto fail;
                if (xmount(err, NULL, dst, NULL, MS_BIND|MS_REMOUNT | MS_RDONLY|MS_NODEV|MS_NOSUID, NULL) < 0)
                        goto fail;
                if ((*ptr++ = xstrdup(err, dst)) == NULL)
                        goto fail;
                *src_end = '\0';
                *dst_end = '\0';
        }
        return (mnt);

 fail:
        for (size_t i = 0; i < size; ++i)
                unmount(mnt[i]);
        array_free(mnt, size);
        return (NULL);
}

static char **
mount_driverstore_files(struct error *err, const char *root, const struct nvc_container *cnt, const char *driverStore, const char *files[], size_t size)
{
        char src[PATH_MAX];
        char dst[PATH_MAX];
        char *src_end, *dst_end, *file;
        char **mnt, **ptr;

        if (path_join(err, src, root, driverStore) < 0)
                return (NULL);
        if (path_resolve_full(err, dst, cnt->cfg.rootfs, driverStore) < 0)
                return (NULL);
        if (file_create(err, dst, NULL, cnt->uid, cnt->gid, MODE_DIR(0755)) < 0)
                return (NULL);

        src_end = src + strlen(src);
        dst_end = dst + strlen(dst);

        mnt = ptr = array_new(err, size + 1); /* NULL terminated. */
        if (mnt == NULL)
                return (NULL);

        for (size_t i = 0; i < size; ++i) {
                file = basename(files[i]);

                if (path_append(err, src, files[i]) < 0)
                        goto fail;
                if (path_append(err, dst, file) < 0)
                        goto fail;
                if (file_create(err, dst, NULL, cnt->uid, cnt->gid, MODE_REG(0555)) < 0)
                        goto fail;

                log_infof("mounting %s at %s", src, dst);

                if (xmount(err, src, dst, NULL, MS_BIND, NULL) < 0)
                        goto fail;
                if (xmount(err, NULL, dst, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NODEV|MS_NOSUID, NULL) < 0)
                        goto fail;
                if ((*ptr++ = xstrdup(err, dst)) == NULL)
                        goto fail;
                *src_end = '\0';
                *dst_end = '\0';
        }

        return (mnt);

 fail:
        for (size_t i = 0; i < size; ++i)
                unmount(mnt[i]);
        array_free(mnt, size);
        return (NULL);
}

static char *
mount_device(struct error *err, const char *root, const struct nvc_container *cnt, const struct nvc_device_node *dev)
{
        struct stat s;
        char src[PATH_MAX];
        char dst[PATH_MAX];
        mode_t mode;
        char *mnt;

        if (path_join(err, src, root, dev->path) < 0)
                return (NULL);
        if (path_resolve_full(err, dst, cnt->cfg.rootfs, dev->path) < 0)
                return (NULL);
        if (xstat(err, src, &s) < 0)
                return (NULL);
        log_infof("mount device node: %s, major: %d minor: %d", src, major(s.st_rdev), minor(dev->id));
        if (s.st_rdev != dev->id) {
                error_setx(err, "invalid device node: %s", src);
                return (NULL);
        }
        if (file_mode(err, src, &mode) < 0)
                return (NULL);
        if (file_create(err, dst, NULL, cnt->uid, cnt->gid, mode) < 0)
                return (NULL);

        log_infof("mounting %s at %s", src, dst);
        if (xmount(err, src, dst, NULL, MS_BIND, NULL) < 0)
                goto fail;
        if (xmount(err, NULL, dst, NULL, MS_BIND|MS_REMOUNT | MS_RDONLY|MS_NOSUID|MS_NOEXEC, NULL) < 0)
                goto fail;
        if ((mnt = xstrdup(err, dst)) == NULL)
                goto fail;
        return (mnt);

 fail:
        unmount(dst);
        return (NULL);
}


static void
unmount(const char *path)
{
        if (path == NULL || str_empty(path))
                return;
        umount2(path, MNT_DETACH);
        file_remove(NULL, path);
}

static int
symlink_library(struct error *err, const char *src, const char *target, const char *linkname, uid_t uid, gid_t gid)
{
        char path[PATH_MAX];
        char *tmp;
        int rv = -1;

        if ((tmp = xstrdup(err, src)) == NULL)
                return (-1);
        if (path_join(err, path, dirname(tmp), linkname) < 0)
                goto fail;

        log_infof("creating symlink %s -> %s", path, target);
        if (file_create(err, path, target, uid, gid, MODE_LNK(0777)) < 0)
                goto fail;
        rv = 0;

 fail:
        free(tmp);
        return (rv);
}

static int
symlink_libraries(struct error *err, const struct nvc_container *cnt, const char * const paths[], size_t size)
{
        char *lib;

        for (size_t i = 0; i < size; ++i) {
                lib = basename(paths[i]);
                if (str_has_prefix(lib, "libcuda.so")) {
                        /* XXX Many applications wrongly assume that libcuda.so exists (e.g. with dlopen). */
                        if (symlink_library(err, paths[i], SONAME_LIBCUDA, "libcuda.so", cnt->uid, cnt->gid) < 0)
                                return (-1);
                } else if (str_has_prefix(lib, "libGLX_nvidia.so")) {
                        /* XXX GLVND requires this symlink for indirect GLX support. */
                        if (symlink_library(err, paths[i], lib, "libGLX_indirect.so.0", cnt->uid, cnt->gid) < 0)
                                return (-1);
                } else if (str_has_prefix(lib, "libnvidia-opticalflow.so")) {
                        /* XXX Fix missing symlink for libnvidia-opticalflow.so. */
                        if (symlink_library(err, paths[i], "libnvidia-opticalflow.so.1", "libnvidia-opticalflow.so", cnt->uid, cnt->gid) < 0)
                                return (-1);
                }
        }
        return (0);
}

static void
filter_libraries(const struct nvc_driver_info *info, char * paths[], size_t *size)
{
        char *lib, *maj;

        /*
         * XXX Filter out any library that matches the major version of RM to prevent us from
         * running into an unsupported configurations (e.g. CUDA compat on Geforce or non-LTS drivers).
         */
        for (size_t i = 0; i < *size; ++i) {
                lib = basename(paths[i]);
                if ((maj = strstr(lib, ".so.")) != NULL) {
                        maj += strlen(".so.");
                        if (strncmp(info->nvrm_version, maj, strspn(maj, "0123456789")))
                                continue;
                }
                paths[i] = NULL;
        }
        array_pack(paths, size);
}

static int
device_mount_dxcore(struct nvc_context *ctx, const struct nvc_container *cnt)
{
        char **drvstore_mnt = NULL;
        size_t drvstore_size = 0;

        // under dxcore we want to mount the driver store key libraries.
        // Devices are not directly visible under dxcore everything is done via /dev/dxg
        // so we only need to mount the per-gpu driver driverStore there are no other per gpu
        // device mounting that needs to be done
        //
        // Note that we are using adapter 0 for all the devices. This is because all
        // the NVIDIA adapters should share the same drivers on a system. If this
        // assumption is changed we will need to query the LUID for each nvc_device
        // and find the matching driver store.
        drvstore_size = (size_t)ctx->dxcore.adapterList[0].driverStoreComponentCount;
        if ((drvstore_mnt = mount_driverstore_files(&ctx->err,
                                                    ctx->cfg.root,
                                                    cnt,
                                                    ctx->dxcore.adapterList[0].pDriverStorePath,
                                                    ctx->dxcore.adapterList[0].pDriverStoreComponents,
                                                    drvstore_size)) == NULL)
        {
                log_errf("failed to mount DriverStore components %s", ctx->dxcore.adapterList[0].pDriverStorePath);
                return (-1);
        }

        return 0;
}

static int
device_mount_native(struct nvc_context *ctx, const struct nvc_container *cnt, const struct nvc_device *dev)
{
        char *dev_mnt = NULL;
        char *proc_mnt = NULL;
        int rv = -1;

        if (!(cnt->flags & OPT_NO_DEVBIND)) {
                if ((dev_mnt = mount_device(&ctx->err, ctx->cfg.root, cnt, &dev->node)) == NULL)
                        goto fail;
        }
        if (!(cnt->flags & OPT_NO_CGROUPS)) {
                if (setup_device_cgroup(&ctx->err, cnt, dev->node.id) < 0)
                        goto fail;
        }

        rv = 0;

 fail:
        if (rv < 0) {
                unmount(proc_mnt);
                unmount(dev_mnt);
        }

        free(proc_mnt);
        free(dev_mnt);

        return (rv);
}


int
nvc_driver_mount(struct nvc_context *ctx, const struct nvc_container *cnt, const struct nvc_driver_info *info)
{
        const char **mnt, **ptr, **tmp;
        size_t nmnt;
        int rv = -1;

        if (validate_context(ctx) < 0)
                return (-1);
        if (validate_args(ctx, cnt != NULL && info != NULL) < 0)
                return (-1);

        if (ns_enter(&ctx->err, cnt->mnt_ns, CLONE_NEWNS) < 0)
                return (-1);

        nmnt = 2 + info->nbins + info->nlibs + cnt->nlibs + info->nlibs32 + info->nipcs + info->ndevs + info->nfirmwares;
        mnt = ptr = (const char **)array_new(&ctx->err, nmnt);
        if (mnt == NULL)
                goto fail;

#if 0
        /* Procfs mount */
        if (ctx->dxcore.initialized)
                log_warn("skipping procfs mount on WSL");
        else if ((*ptr++ = mount_procfs(&ctx->err, ctx->cfg.root, cnt)) == NULL)
                goto fail;

        /* Application profile mount */
        if (cnt->flags & OPT_GRAPHICS_LIBS) {
                if (ctx->dxcore.initialized)
                        log_warn("skipping app profile mount on WSL");
                else if ((*ptr++ = mount_app_profile(&ctx->err, cnt)) == NULL)
                        goto fail;
        }
#endif

        /* Host binary and library mounts */
        if (cnt->cfg.cudart_dir != NULL)
            mount_directory(&ctx->err, ctx->cfg.root, cnt, cnt->cfg.cudart_dir);
        if (info->bins != NULL && info->nbins > 0) {
                if ((tmp = (const char **)mount_files(&ctx->err, ctx->cfg.root, cnt, cnt->cfg.bins_dir, info->bins, info->nbins)) == NULL)
                        goto fail;
                ptr = array_append(ptr, tmp, array_size(tmp));
                free(tmp);
        }
        if (info->libs != NULL && info->nlibs > 0) {
                if ((tmp = (const char **)mount_files(&ctx->err, ctx->cfg.root, cnt, cnt->cfg.libs_dir, info->libs, info->nlibs)) == NULL)
                        goto fail;
                ptr = array_append(ptr, tmp, array_size(tmp));
                free(tmp);
        }
        if ((cnt->flags & OPT_COMPAT32) && info->libs32 != NULL && info->nlibs32 > 0) {
                if ((tmp = (const char **)mount_files(&ctx->err, ctx->cfg.root, cnt, cnt->cfg.libs32_dir, info->libs32, info->nlibs32)) == NULL)
                        goto fail;
                ptr = array_append(ptr, tmp, array_size(tmp));
                free(tmp);
        }
        if (symlink_libraries(&ctx->err, cnt, mnt, (size_t)(ptr - mnt)) < 0)
                goto fail;

        /* Container library mounts */
        if (cnt->libs != NULL && cnt->nlibs > 0) {
                size_t nlibs = cnt->nlibs;
                char **libs = array_copy(&ctx->err, (const char * const *)cnt->libs, cnt->nlibs);
                if (libs == NULL)
                        goto fail;

                filter_libraries(info, libs, &nlibs);
                if ((tmp = (const char **)mount_files(&ctx->err, cnt->cfg.rootfs, cnt, cnt->cfg.libs_dir, libs, nlibs)) == NULL) {
                        free(libs);
                        goto fail;
                }
                ptr = array_append(ptr, tmp, array_size(tmp));
                free(tmp);
                free(libs);
        }

        /* Device mounts */
        for (size_t i = 0; i < info->ndevs; ++i) {
                /* On WSL2 we only mount the /dev/dxg device and as such these checks are not applicable. */
                if (!ctx->dxcore.initialized) {
                        /* XXX Only compute libraries require specific devices (e.g. UVM). */
                        if (!(cnt->flags & OPT_COMPUTE_LIBS) && major(info->devs[i].id) != NV_DEVICE_MAJOR)
                                continue;
                        /* XXX Only display capability requires the modeset device. */
                        if (!(cnt->flags & OPT_DISPLAY) && minor(info->devs[i].id) == NV_MODESET_DEVICE_MINOR)
                                continue;
                }
                if (!(cnt->flags & OPT_NO_DEVBIND)) {
                        if ((*ptr++ = mount_device(&ctx->err, ctx->cfg.root, cnt, &info->devs[i])) == NULL)
                                goto fail;
                }
                if (!(cnt->flags & OPT_NO_CGROUPS)) {
                        if (setup_device_cgroup(&ctx->err, cnt, info->devs[i].id) < 0)
                                goto fail;
                }
        }
        rv = 0;

 fail:
        if (rv < 0) {
                for (size_t i = 0; mnt != NULL && i < nmnt; ++i)
                        unmount(mnt[i]);
                assert_func(ns_enter_at(NULL, ctx->mnt_ns, CLONE_NEWNS));
        } else {
                rv = ns_enter_at(&ctx->err, ctx->mnt_ns, CLONE_NEWNS);
        }

        array_free((char **)mnt, nmnt);
        return (rv);
}

int
nvc_device_mount(struct nvc_context *ctx, const struct nvc_container *cnt, const struct nvc_device *dev)
{
        int rv = -1;

        if (validate_context(ctx) < 0)
                return (-1);
        if (validate_args(ctx, cnt != NULL && dev != NULL) < 0)
                return (-1);

        if (ns_enter(&ctx->err, cnt->mnt_ns, CLONE_NEWNS) < 0)
                return (-1);

        if (ctx->dxcore.initialized)
                rv = device_mount_dxcore(ctx, cnt);
        else rv = device_mount_native(ctx, cnt, dev);

        if (rv < 0)
                assert_func(ns_enter_at(NULL, ctx->mnt_ns, CLONE_NEWNS));
        else rv = ns_enter_at(&ctx->err, ctx->mnt_ns, CLONE_NEWNS);

        return (rv);
}
