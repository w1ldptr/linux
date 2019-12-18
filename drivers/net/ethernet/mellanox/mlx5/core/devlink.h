/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2019, Mellanox Technologies */

#ifndef __MLX5_DEVLINK_H__
#define __MLX5_DEVLINK_H__

#include <net/devlink.h>

struct mlx5_eswitch;

struct devlink *mlx5_devlink_alloc(void);
void mlx5_devlink_free(struct devlink *devlink);
int mlx5_devlink_register(struct devlink *devlink, struct device *dev);
void mlx5_devlink_unregister(struct devlink *devlink);

int mlx5_devlink_slices_create(struct mlx5_eswitch *esw);
void mlx5_devlink_slices_destroy(struct mlx5_eswitch *esw);

#endif /* __MLX5_DEVLINK_H__ */
