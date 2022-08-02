/*
 * Copyright (c) 2017-2018, NVIDIA CORPORATION. All rights reserved.
 */

#ifndef HEADER_DRIVER_H
#define HEADER_DRIVER_H

#include <sys/types.h>

#include <stdbool.h>

#include "error.h"
#include "dxcore.h"

struct driver_device;

int driver_init(struct error *, struct dxcore_context *, const char *, uid_t, gid_t);
int driver_shutdown(struct error *);
int driver_get_rm_version(struct error*, char **);
int driver_get_cuda_version(struct error*, char **);
int driver_get_device_count(struct error*, unsigned int *);
int driver_get_device(struct error*, unsigned int, struct driver_device **);
int driver_get_device_minor(struct error*, struct driver_device *, unsigned int *);
int driver_get_device_busid(struct error*, struct driver_device *, char **);
int driver_get_device_uuid(struct error*, struct driver_device *, char **);
int driver_get_device_arch(struct error*, struct driver_device *, char **);
int driver_get_device_model(struct error*, struct driver_device *, char **);
int driver_get_device_brand(struct error*, struct driver_device *, char **);
int driver_get_device_id(struct error*, struct driver_device *, unsigned int *);
int driver_create_cxpu_instance(struct error *err, struct driver_device *dev, char *instance_id);
int driver_destroy_cxpu_instance(struct error *err, struct driver_device *dev, char *instance_id);
int driver_set_cxpu_instance_memory_limit(struct error *err, struct driver_device *dev, char *instance_id, unsigned int type, unsigned long long bytes);

#endif /* HEADER_DRIVER_H */
