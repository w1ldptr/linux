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
	WARN_ON(atomic64_read(&mdev->ipsec_offloads_count) == U64_MAX);
	atomic64_inc(&mdev->ipsec_offloads_count);
}

static inline void mlx5_eswitch_unblock_ipsec_mode(struct mlx5_core_dev *mdev)
{
	WARN_ON(atomic64_read(&mdev->ipsec_offloads_count) == 0);
	atomic64_dec(&mdev->ipsec_offloads_count);
}

/* The caller must hold devlink->lock */
static inline bool mlx5_eswitch_ipsec_offloads_enabled(struct mlx5_core_dev *mdev)
{
	return !!atomic64_read(&mdev->ipsec_offloads_count);
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
