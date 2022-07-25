/*
 * Copyright (c) 2017-2018, NVIDIA CORPORATION. All rights reserved.
 */

#include <sys/types.h>

#include <inttypes.h>

#include "xpuml.h"

#include "nvc_internal.h"

#include "driver.h"
#include "error.h"
#include "utils.h"
#include "rpc.h"
#include "xfuncs.h"

#define MAX_DEVICES     64

void driver_program_1(struct svc_req *, register SVCXPRT *);

static struct driver_device {
        xpumlDevice_t xpuml;
} device_handles[MAX_DEVICES];

static struct driver {
        struct rpc rpc;
        bool initialized;
        char root[PATH_MAX];
        char xpuml_path[PATH_MAX];
        uid_t uid;
        gid_t gid;
        void *xpuml_dl;
} global_driver_context;

#define call_xpuml(err, ctx, sym, ...) __extension__ ({                                                 \
        union {void *ptr; __typeof__(&sym) fn;} u_;                                                    \
        xpumlReturn_t r_;                                                                               \
                                                                                                       \
        dlerror();                                                                                     \
        u_.ptr = dlsym((ctx)->xpuml_dl, #sym);                                                          \
        r_ = (dlerror() == NULL) ? (*u_.fn)(__VA_ARGS__) : XPUML_ERROR_FUNCTION_NOT_FOUND;              \
        if (r_ != XPUML_SUCCESS)                                                                        \
                error_set_xpuml((err), (ctx)->xpuml_dl, r_, "xpuml error");                               \
        (r_ == XPUML_SUCCESS) ? 0 : -1;                                                                 \
})

static struct driver *
driver_get_context(void)
{
        return &global_driver_context;
}

int
driver_program_1_freeresult(maybe_unused SVCXPRT *svc, xdrproc_t xdr_result, caddr_t res)
{
        xdr_free(xdr_result, res);
        return (1);
}

int
driver_init(struct error *err, struct dxcore_context *dxcore, const char *root, uid_t uid, gid_t gid)
{
        int ret;
        struct rpc_prog rpc_prog = {0};;
        struct driver *ctx = driver_get_context();
        struct driver_init_res res = {0};

        rpc_prog = (struct rpc_prog){
                .name = "driver",
                .id = DRIVER_PROGRAM,
                .version = DRIVER_VERSION,
                .dispatch = driver_program_1,
        };

        *ctx = (struct driver){
                .rpc = {0},
                .root = {0},
                .xpuml_path = SONAME_LIBXPUML,
                .uid = uid,
                .gid = gid,
                .xpuml_dl = NULL,
        };
        strcpy(ctx->root, root);

        if (dxcore->initialized) {
                memset(ctx->xpuml_path, 0, strlen(ctx->xpuml_path));
                if (path_join(err, ctx->xpuml_path, dxcore->adapterList[0].pDriverStorePath, SONAME_LIBXPUML) < 0)
                        goto fail;
        }

        if (rpc_init(err, &ctx->rpc, &rpc_prog) < 0)
                goto fail;

        ret = call_rpc(err, &ctx->rpc, &res, driver_init_1);
        xdr_free((xdrproc_t)xdr_driver_init_res, (caddr_t)&res);
        if (ret < 0)
                goto fail;

        ctx->initialized = true;
        return (0);

 fail:
        rpc_shutdown(NULL, &ctx->rpc, true);
        return (-1);
}

bool_t
driver_init_1_svc(ptr_t ctxptr, driver_init_res *res, maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;

        memset(res, 0, sizeof(*res));

        /* Preload glibc libraries to avoid symbols mismatch after changing root. */
        if (!str_equal(ctx->root, "/")) {
                if (xdlopen(err, "libm.so.6", RTLD_NOW) == NULL)
                        goto fail;
                if (xdlopen(err, "librt.so.1", RTLD_NOW) == NULL)
                        goto fail;
                if (xdlopen(err, "libpthread.so.0", RTLD_NOW) == NULL)
                        goto fail;

                if (chroot(ctx->root) < 0 || chdir("/") < 0) {
                        error_set(err, "change root failed");
                        goto fail;
                }
        }

        /*
         * Drop privileges and capabilities for security reasons.
         *
         * We might be inside a user namespace with full capabilities, this should also help prevent XPUML
         * from potentially adjusting the host device nodes based on the (wrong) driver registry parameters.
         *
         * If we are not changing group, then keep our supplementary groups as well.
         * This is arguable but allows us to support unprivileged processes (i.e. without CAP_SETGID) and user namespaces.
         */
        if (perm_drop_privileges(err, ctx->uid, ctx->gid, (getegid() != ctx->gid)) < 0)
                 goto fail;
        if (perm_set_capabilities(err, CAP_PERMITTED, NULL, 0) < 0)
                 goto fail;

        /* Load and initialize the XPUML library. */
        if ((ctx->xpuml_dl = xdlopen(err, ctx->xpuml_path, RTLD_NOW)) == NULL)
                goto fail;

        if (call_xpuml(err, ctx, xpumlInit) < 0)
                goto fail;

        return (true);

 fail:
        error_to_xdr(err, res);
        return (true);
}

int
driver_shutdown(struct error *err)
{
        int ret;
        struct driver *ctx = driver_get_context();
        struct driver_shutdown_res res = {0};

        if (ctx->initialized == false)
                return (0);

        ret = call_rpc(err, &ctx->rpc, &res, driver_shutdown_1);
        xdr_free((xdrproc_t)xdr_driver_shutdown_res, (caddr_t)&res);
        if (rpc_shutdown(err, &ctx->rpc, (ret < 0)) < 0)
                return (-1);

        ctx->initialized = false;
        return (0);
}

bool_t
driver_shutdown_1_svc(ptr_t ctxptr, driver_shutdown_res *res, maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;
        int rv = -1;

        memset(res, 0, sizeof(*res));
        if ((rv = call_xpuml(err, ctx, xpumlShutdown)) < 0)
                goto fail;
        svc_exit();

 fail:
        if (rv < 0)
                error_to_xdr(err, res);
        xdlclose(NULL, ctx->xpuml_dl);
        return (true);
}

int
driver_get_rm_version(struct error *err, char **version)
{
        struct driver *ctx = driver_get_context();
        struct driver_get_rm_version_res res = {0};
        int rv = -1;

        if (call_rpc(err, &ctx->rpc, &res, driver_get_rm_version_1) < 0)
                goto fail;
        if ((*version = xstrdup(err, res.driver_get_rm_version_res_u.vers)) == NULL)
                goto fail;
        rv = 0;

 fail:
        xdr_free((xdrproc_t)xdr_driver_get_rm_version_res, (caddr_t)&res);
        return (rv);
}

bool_t
driver_get_rm_version_1_svc(ptr_t ctxptr, driver_get_rm_version_res *res, maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;
        char buf[XPUML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE];

        memset(res, 0, sizeof(*res));
        if (call_xpuml(err, ctx, xpumlSystemGetDriverVersion, buf, sizeof(buf)) < 0)
                goto fail;
        if ((res->driver_get_rm_version_res_u.vers = xstrdup(err, buf)) == NULL)
                goto fail;
        return (true);

 fail:
        error_to_xdr(err, res);
        return (true);
}

int
driver_get_cuda_version(struct error *err, char **version)
{
        struct driver *ctx = driver_get_context();
        struct driver_get_cuda_version_res res = {0};
        int rv = -1;

        if (call_rpc(err, &ctx->rpc, &res, driver_get_cuda_version_1) < 0)
                goto fail;
        if (xasprintf(err, version, "%u.%u", res.driver_get_cuda_version_res_u.vers.major,
            res.driver_get_cuda_version_res_u.vers.minor) < 0)
                goto fail;
        rv = 0;

 fail:
        xdr_free((xdrproc_t)xdr_driver_get_cuda_version_res, (caddr_t)&res);
        return (rv);
}

bool_t
driver_get_cuda_version_1_svc(ptr_t ctxptr, driver_get_cuda_version_res *res, maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;
        int version = 1010;

        memset(res, 0, sizeof(*res));
#if 0
        if (call_xpuml(err, ctx, xpumlSystemGetCudaDriverVersion, &version) < 0)
                goto fail;
#endif

        res->driver_get_cuda_version_res_u.vers.major = (unsigned int)version / 1000;
        res->driver_get_cuda_version_res_u.vers.minor = (unsigned int)version % 100 / 10;
        return (true);

 fail:
        error_to_xdr(err, res);
        return (true);
}

int
driver_get_device_count(struct error *err, unsigned int *count)
{
        struct driver *ctx = driver_get_context();
        struct driver_get_device_count_res res = {0};
        int rv = -1;

        if (call_rpc(err, &ctx->rpc, &res, driver_get_device_count_1) < 0)
                goto fail;
        *count = res.driver_get_device_count_res_u.count;
        rv = 0;

 fail:
        xdr_free((xdrproc_t)xdr_driver_get_device_count_res, (caddr_t)&res);
        return (rv);
}

bool_t
driver_get_device_count_1_svc(ptr_t ctxptr, driver_get_device_count_res *res, maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;
        unsigned int count;

        memset(res, 0, sizeof(*res));
        if (call_xpuml(err, ctx, xpumlDeviceGetCount, &count) < 0)
                goto fail;

        res->driver_get_device_count_res_u.count = count;
        return (true);

 fail:
        error_to_xdr(err, res);
        return (true);
}

int
driver_get_device(struct error *err, unsigned int idx, struct driver_device **dev)
{
        struct driver *ctx = driver_get_context();
        struct driver_get_device_res res = {0};
        int rv = -1;

        if (call_rpc(err, &ctx->rpc, &res, driver_get_device_1, idx) < 0)
                goto fail;
        *dev = (struct driver_device *)res.driver_get_device_res_u.dev;
        rv = 0;

 fail:
        xdr_free((xdrproc_t)xdr_driver_get_device_res, (caddr_t)&res);
        return (rv);
}

bool_t
driver_get_device_1_svc(ptr_t ctxptr, u_int idx, driver_get_device_res *res, maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;

        memset(res, 0, sizeof(*res));
        if (idx >= MAX_DEVICES) {
                error_setx(err, "too many devices");
                goto fail;
        }
        if (call_xpuml(err, ctx, xpumlDeviceGetHandleByIndex, (unsigned)idx, &device_handles[idx].xpuml) < 0)
                goto fail;

        res->driver_get_device_res_u.dev = (ptr_t)&device_handles[idx];
        return (true);

 fail:
        error_to_xdr(err, res);
        return (true);
}

int
driver_get_device_minor(struct error *err, struct driver_device *dev, unsigned int *minor)
{
        struct driver *ctx = driver_get_context();
        struct driver_get_device_minor_res res = {0};
        int rv = -1;

        if (call_rpc(err, &ctx->rpc, &res, driver_get_device_minor_1, (ptr_t)dev) < 0)
                goto fail;
        *minor = res.driver_get_device_minor_res_u.minor;
        rv = 0;

 fail:
        xdr_free((xdrproc_t)xdr_driver_get_device_minor_res, (caddr_t)&res);
        return (rv);
}

bool_t
driver_get_device_minor_1_svc(ptr_t ctxptr, ptr_t dev, driver_get_device_minor_res *res, maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;
        struct driver_device *handle = (struct driver_device *)dev;
        unsigned int minor = 0;

        memset(res, 0, sizeof(*res));
#if 0
        if (call_xpuml(err, ctx, xpumlDeviceGetMinorNumber, handle->xpuml, &minor) < 0)
                goto fail;
#endif
        res->driver_get_device_minor_res_u.minor = minor;
        return (true);

 fail:
        error_to_xdr(err, res);
        return (true);
}

int
driver_get_device_busid(struct error *err, struct driver_device *dev, char **busid)
{
        struct driver *ctx = driver_get_context();
        struct driver_get_device_busid_res res = {0};
        int rv = -1;

        if (call_rpc(err, &ctx->rpc, &res, driver_get_device_busid_1, (ptr_t)dev) < 0)
                goto fail;
        if ((*busid = xstrdup(err, res.driver_get_device_busid_res_u.busid)) == NULL)
                goto fail;
        rv = 0;

 fail:
        xdr_free((xdrproc_t)xdr_driver_get_device_busid_res, (caddr_t)&res);
        return (rv);
}

bool_t
driver_get_device_busid_1_svc(ptr_t ctxptr, ptr_t dev, driver_get_device_busid_res *res, maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;
        struct driver_device *handle = (struct driver_device *)dev;
        xpumlPciInfo_t pci;

        memset(res, 0, sizeof(*res));
        if (call_xpuml(err, ctx, xpumlDeviceGetPciInfo, handle->xpuml, &pci) < 0)
                goto fail;

        if (xasprintf(err, &res->driver_get_device_busid_res_u.busid, "%08x:%02x:%02x.0", pci.domain, pci.bus, pci.device) < 0)
                goto fail;
        return (true);

 fail:
        error_to_xdr(err, res);
        return (true);
}

int
driver_get_device_uuid(struct error *err, struct driver_device *dev, char **uuid)
{
        struct driver *ctx = driver_get_context();
        struct driver_get_device_uuid_res res = {0};
        int rv = -1;

        if (call_rpc(err, &ctx->rpc, &res, driver_get_device_uuid_1, (ptr_t)dev) < 0)
                goto fail;
        if ((*uuid = xstrdup(err, res.driver_get_device_uuid_res_u.uuid)) == NULL)
                goto fail;
        rv = 0;

 fail:
        xdr_free((xdrproc_t)xdr_driver_get_device_uuid_res, (caddr_t)&res);
        return (rv);
}

bool_t
driver_get_device_uuid_1_svc(ptr_t ctxptr, ptr_t dev, driver_get_device_uuid_res *res, maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;
        struct driver_device *handle = (struct driver_device *)dev;
        char buf[XPUML_DEVICE_UUID_BUFFER_SIZE];

        strcpy(buf, "kunlun2 uuid");

        memset(res, 0, sizeof(*res));
#if 0
        if (call_xpuml(err, ctx, xpumlDeviceGetUUID, handle->xpuml, buf, sizeof(buf)) < 0)
                goto fail;
#endif
        if ((res->driver_get_device_uuid_res_u.uuid = xstrdup(err, buf)) == NULL)
                goto fail;
        return (true);

 fail:
        error_to_xdr(err, res);
        return (true);
}

int
driver_get_device_model(struct error *err, struct driver_device *dev, char **model)
{
        struct driver *ctx = driver_get_context();
        struct driver_get_device_model_res res = {0};
        int rv = -1;

        if (call_rpc(err, &ctx->rpc, &res, driver_get_device_model_1, (ptr_t)dev) < 0)
                goto fail;
        if ((*model = xstrdup(err, res.driver_get_device_model_res_u.model)) == NULL)
                goto fail;
        rv = 0;

 fail:
        xdr_free((xdrproc_t)xdr_driver_get_device_model_res, (caddr_t)&res);
        return (rv);
}

bool_t
driver_get_device_model_1_svc(ptr_t ctxptr, ptr_t dev, driver_get_device_model_res *res, maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;
        struct driver_device *handle = (struct driver_device *)dev;
        char buf[XPUML_DEVICE_NAME_BUFFER_SIZE];

        strcpy(buf, "kunlun2");

        memset(res, 0, sizeof(*res));
#if 0
        if (call_xpuml(err, ctx, xpumlDeviceGetName, handle->xpuml, buf, sizeof(buf)) < 0)
                goto fail;
#endif
        if ((res->driver_get_device_model_res_u.model = xstrdup(err, buf)) == NULL)
                goto fail;
        return (true);

 fail:
        error_to_xdr(err, res);
        return (true);
}

int
driver_get_device_brand(struct error *err, struct driver_device *dev, char **brand)
{
        struct driver *ctx = driver_get_context();
        struct driver_get_device_brand_res res = {0};
        int rv = -1;

        if (call_rpc(err, &ctx->rpc, &res, driver_get_device_brand_1, (ptr_t)dev) < 0)
                goto fail;
        if ((*brand = xstrdup(err, res.driver_get_device_brand_res_u.brand)) == NULL)
                goto fail;
        rv = 0;

 fail:
        xdr_free((xdrproc_t)xdr_driver_get_device_brand_res, (caddr_t)&res);
        return (rv);
}

bool_t
driver_get_device_brand_1_svc(ptr_t ctxptr, ptr_t dev, driver_get_device_brand_res *res, maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;
        struct driver_device *handle = (struct driver_device *)dev;
//        xpumlBrandType_t brand;
        const char *buf;

        memset(res, 0, sizeof(*res));
#if 0
        if (call_xpuml(err, ctx, xpumlDeviceGetBrand, handle->xpuml, &brand) < 0)
                goto fail;
        switch (brand) {
        case XPUML_BRAND_QUADRO:
                buf = "Quadro";
                break;
        case XPUML_BRAND_NVIDIA_CLOUD_GAMING:
                buf = "CloudGaming";
                break;
        default:
                buf = "Unknown";
        }
#endif
        buf = "Kunlun";
        if ((res->driver_get_device_brand_res_u.brand = xstrdup(err, buf)) == NULL)
                goto fail;
        return (true);

 fail:
        error_to_xdr(err, res);
        return (true);
}

int
driver_get_device_arch(struct error *err, struct driver_device *dev, char **arch)
{
        struct driver *ctx = driver_get_context();
        struct driver_get_device_arch_res res = {0};
        int rv = -1;

        if (call_rpc(err, &ctx->rpc, &res, driver_get_device_arch_1, (ptr_t)dev) < 0)
                goto fail;
        if (xasprintf(err, arch, "%u.%u", res.driver_get_device_arch_res_u.arch.major,
            res.driver_get_device_arch_res_u.arch.minor) < 0)
                goto fail;
        rv = 0;

 fail:
        xdr_free((xdrproc_t)xdr_driver_get_device_arch_res, (caddr_t)&res);
        return (rv);
}

bool_t
driver_get_device_arch_1_svc(ptr_t ctxptr, ptr_t dev, driver_get_device_arch_res *res, maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;
        struct driver_device *handle = (struct driver_device *)dev;
        int major = 1, minor = 1;

        memset(res, 0, sizeof(*res));
#if 0
        if (call_xpuml(err, ctx, xpumlDeviceGetCudaComputeCapability, handle->xpuml, &major, &minor) < 0)
                goto fail;
#endif

        res->driver_get_device_arch_res_u.arch.major = (unsigned int)major;
        res->driver_get_device_arch_res_u.arch.minor = (unsigned int)minor;
        return (true);

 fail:
        error_to_xdr(err, res);
        return (true);
}

int
driver_set_device_memory_limit(struct error *err, struct driver_device *dev, char *user_id, unsigned int type, unsigned long long bytes)
{
        struct driver *ctx = driver_get_context();
        struct driver_set_device_memory_limit_res res = {0};
        int rv = -1;

        if (call_rpc(err, &ctx->rpc, &res, driver_set_device_memory_limit_1, (ptr_t)dev, (ptr_t)user_id, type, bytes) < 0)
                goto fail;
        rv = 0;

 fail:
        xdr_free((xdrproc_t)xdr_driver_set_device_memory_limit_res, (caddr_t)&res);
        return (rv);
}

bool_t
driver_set_device_memory_limit_1_svc(ptr_t ctxptr, ptr_t dev, ptr_t user_id, unsigned int type, uint64_t limit_inbytes,
        driver_set_device_memory_limit_res *res,
        maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;
        struct driver_device *handle = (struct driver_device *)dev;

        memset(res, 0, sizeof(*res));
        call_xpuml(err, ctx, xpumlDeviceSetCxpuInstanceMemoryLimit, handle->xpuml, (char *)user_id, type, limit_inbytes);

        return (true);

 fail:
        error_to_xdr(err, res);
        return (true);
}

int
driver_create_device_cxpu(struct error *err, struct driver_device *dev, char *user_id)
{
        struct driver *ctx = driver_get_context();
        struct driver_create_device_cxpu_res res= {0};
        int rv = -1;

        if (call_rpc(err, &ctx->rpc, &res, driver_create_device_cxpu_1, (ptr_t)dev, (ptr_t)user_id) < 0)
                goto fail;
        rv = 0;

 fail:
        xdr_free((xdrproc_t)xdr_driver_create_device_cxpu_res, (caddr_t)&res);
        return (rv);
}

bool_t
driver_create_device_cxpu_1_svc(ptr_t ctxptr, ptr_t dev, ptr_t user_id,
        driver_create_device_cxpu_res *res, maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;
        struct driver_device *handle = (struct driver_device *)dev;

        memset(res, 0, sizeof(*res));
        call_xpuml(err, ctx, xpumlDeviceCreateCxpuInstance, handle->xpuml, (char *)user_id);

        return (true);
 fail:
        error_to_xdr(err, res);
        return (true);
}

int
driver_destroy_device_cxpu(struct error *err, struct driver_device *dev, char *user_id)
{
        struct driver *ctx = driver_get_context();
        struct driver_destroy_device_cxpu_res res= {0};
        int rv = -1;

        if (call_rpc(err, &ctx->rpc, &res, driver_destroy_device_cxpu_1, (ptr_t)dev, (ptr_t)user_id) < 0)
                goto fail;

        rv = 0;

 fail:
        xdr_free((xdrproc_t)xdr_driver_destroy_device_cxpu_res, (caddr_t)&res);
        return (rv);
}

bool_t
driver_destroy_device_cxpu_1_svc(ptr_t ctxptr, ptr_t dev, ptr_t user_id,
        driver_destroy_device_cxpu_res *res, maybe_unused struct svc_req *req)
{
        struct error *err = (struct error[]){0};
        struct driver *ctx = (struct driver *)ctxptr;
        struct driver_device *handle = (struct driver_device *)dev;

        memset(res, 0, sizeof(*res));
        call_xpuml(err, ctx, xpumlDeviceDestroyCxpuInstance, handle->xpuml, (char *)user_id);

        return (true);

 fail:
        error_to_xdr(err, res);
        return (true);
}
