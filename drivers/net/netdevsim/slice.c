// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Mellanox Technologies */

#include <linux/device.h>
#include <linux/etherdevice.h>
#include <linux/inet.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/rtnetlink.h>
#include <net/devlink.h>
#include <uapi/linux/devlink.h>

#include "netdevsim.h"

static int
nsim_hw_addr_set(struct devlink_slice *devlink_slice, u8 *hw_addr,
		 struct netlink_ext_ack *extack)
{
	struct nsim_bus_dev *nsim_bus_dev;
	struct nsim_slice *nsim_slice;
	int slice_index;

	nsim_slice = devlink_slice_priv(devlink_slice);
	nsim_bus_dev = nsim_slice->nsim_bus_dev;
	slice_index = nsim_slice->slice_index;

	ether_addr_copy(nsim_bus_dev->vfconfigs[slice_index].vf_mac,
			hw_addr);
	return 0;
}

static int
nsim_hw_addr_get(struct devlink_slice *devlink_slice, u8 *hw_addr,
		 struct netlink_ext_ack *extack)
{
	struct nsim_bus_dev *nsim_bus_dev;
	struct nsim_slice *nsim_slice;
	int slice_index;

	nsim_slice = devlink_slice_priv(devlink_slice);
	nsim_bus_dev = nsim_slice->nsim_bus_dev;
	slice_index = nsim_slice->slice_index;

	ether_addr_copy(hw_addr,
			nsim_bus_dev->vfconfigs[slice_index].vf_mac);
	return 0;
}

static struct devlink_slice_ops slice_ops = {
	.hw_addr_set = nsim_hw_addr_set,
	.hw_addr_get = nsim_hw_addr_get,
	.hw_addr_len = ETH_ALEN,
};

int nsim_dev_slices_create(struct nsim_dev *nsim_dev, struct devlink *devlink)
{
	int max_vfs = nsim_dev->nsim_bus_dev->max_vfs;
	struct devlink_slice_attrs attrs;
	int err;
	int vf;

	nsim_dev->slices = kcalloc(max_vfs, sizeof(*nsim_dev->slices),
				   GFP_KERNEL);
	if (!nsim_dev->slices)
		return -ENOMEM;

	for (vf = 0; vf < max_vfs; vf++) {
		struct nsim_slice *nsim_slice = &nsim_dev->slices[vf];
		struct devlink_slice_rate *devlink_rate;
		struct devlink_slice *devlink_slice;

		nsim_slice->nsim_bus_dev = nsim_dev->nsim_bus_dev;
		devlink_slice_attrs_pci_vf_init(&attrs, 0, vf);
		devlink_slice = devlink_slice_create(devlink, vf,
						     &slice_ops,
						     &attrs,
						     nsim_slice);
		if (IS_ERR(devlink_slice)) {
			err = PTR_ERR(devlink_slice);
			goto err_slices_destroy;
		}
		nsim_slice->devlink_slice = devlink_slice;
		nsim_slice->slice_index = vf;

		devlink_rate = devlink_slice_rate_leaf_create(devlink_slice,
							      nsim_slice);
		if (IS_ERR(devlink_rate)) {
			vf++;
			err = PTR_ERR(devlink_rate);
			goto err_slices_destroy;
		}
		nsim_slice->devlink_rate = devlink_rate;
	}

	return 0;

err_slices_destroy:
	for (vf--; vf >= 0; vf--) {
		struct nsim_slice *nsim_slice = &nsim_dev->slices[vf];
		struct devlink_slice_rate *devlink_rate;

		devlink_rate = nsim_slice->devlink_rate;
		if (devlink_rate)
			devlink_slice_rate_leaf_destroy(devlink_rate);
		devlink_slice_destroy(nsim_slice->devlink_slice);
	}
	return err;
}

void nsim_dev_slices_destroy(struct nsim_dev *nsim_dev)
{
	int vf;

	for (vf = 0; vf < nsim_dev->nsim_bus_dev->max_vfs; vf++) {
		struct nsim_slice *nsim_slice = &nsim_dev->slices[vf];

		devlink_slice_rate_leaf_destroy(nsim_slice->devlink_rate);
		devlink_slice_destroy(nsim_slice->devlink_slice);
	}
}

