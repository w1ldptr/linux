/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_LIB_IPSEC_H__
#define __MLX5_LIB_IPSEC_H__

#include <linux/mlx5/driver.h>
#include "eswitch.h"

#ifdef CONFIG_MLX5_EN_IPSEC

/* The caller must hold devlink->lock */
static inline void mlx5_eswitch_block_ipsec_mode(struct mlx5_core_dev *mdev)
{
	mdev->num_ipsec_offloads++;
}

static inline void mlx5_eswitch_unblock_ipsec_mode(struct mlx5_core_dev *mdev)
{
	mdev->num_ipsec_offloads--;
}

/* The caller must hold devlink->lock */
static inline bool mlx5_eswitch_ipsec_offloads_enabled(struct mlx5_core_dev *mdev)
{
	return mdev->num_ipsec_offloads;
}
#else
static inline void mlx5_eswitch_block_ipsec_mode(struct mlx5_core_dev *mdev) { }

static inline void mlx5_eswitch_unblock_ipsec_mode(struct mlx5_core_dev *mdev) { }

static inline bool mlx5_eswitch_ipsec_offloads_enabled(struct mlx5_core_dev *mdev)
{
	return false;
}
#endif /* CONFIG_MLX5_EN_IPSEC */

#endif /* __MLX5_LIB_IPSEC_H__ */
