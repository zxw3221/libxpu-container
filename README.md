# libxpu-container

[![GitHub license](https://img.shields.io/badge/license-New%20BSD-blue.svg?style=flat-square)](https://raw.githubusercontent.com/zxw3221/libxpu-container/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/zxw3221/libxpu-container/all.svg?style=flat-square)](https://github.com/zxw3221/libxpu-container/releases)

This repository provides a library and a simple CLI utility to automatically configure GNU/Linux containers leveraging XPU hardware.\
The implementation relies on kernel primitives and is designed to be agnostic of the container runtime.

## Installing the library
### From packages
Get the [libxpu-container package](https://github.com/zxw3221/xpu-container-toolkit/releases) for your Linux distribution.

Install the packages:
```bash
libxpu-container0
libxpu-container-tools
```

### From sources
With Docker:
```bash
# Generate docker images for a supported <os><version>
make {ubuntu18.04, ubuntu16.04, debian10, debian9, centos7, amazonlinux2, opensuse-leap15.1}

# Or generate docker images for all supported distributions in the dist/ directory
make docker
````

The resulting images have the name `zxw3221/libxpu-container/<os>:<version>`

Without Docker:
```bash
make install

# Alternatively in order to customize the installation paths
DESTDIR=/path/to/root make install prefix=/usr
```

## Using the library
### Container runtime example
Refer to the [xpu-container-runtime](https://github.com/zxw3221/xpu-container-runtime) project.

### Command line example

```bash
# Setup a new set of namespaces
cd $(mktemp -d) && mkdir rootfs
sudo unshare --mount --pid --fork

# Setup a rootfs based on Ubuntu 16.04 inside the new namespaces
curl http://cdimage.ubuntu.com/ubuntu-base/releases/16.04/release/ubuntu-base-16.04.6-base-amd64.tar.gz | tar -C rootfs -xz
useradd -R $(realpath rootfs) -U -u 1000 -s /bin/bash xpu
mount --bind rootfs rootfs
mount --make-private rootfs
cd rootfs

# Mount standard filesystems
mount -t proc none proc
mount -t sysfs none sys
mount -t tmpfs none tmp
mount -t tmpfs none run

# Isolate the first GPU device along with basic utilities
xpu-container-cli --load-kmods configure --ldconfig=@/sbin/ldconfig.real --no-cgroups --utility --device 0 $(pwd)

# Change into the new rootfs
pivot_root . mnt
umount -l mnt
exec chroot --userspec 1000:1000 . env -i bash

# Run xpu-smi from within the container
xpu-smi -L
```

## Copyright and License

This project is released under the [BSD 3-clause license](https://github.com/zxw3221/libxpu-container/blob/main/LICENSE).

Additionally, this project can be dynamically linked with libelf from the elfutils package (https://sourceware.org/elfutils), in which case additional terms apply.\
Refer to [NOTICE](https://github.com/zxw3221/libxpu-container/blob/main/NOTICE) for more information.

## Issues and Contributing

[Checkout the Contributing document!](CONTRIBUTING.md)

* Please let us know by [filing a new issue](https://github.com/zxw3221/libxpu-container/issues/new)
* You can contribute by opening a [pull request](https://help.github.com/articles/using-pull-requests/)
