// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2019 Mellanox Technologies */

#include <devlink.h>

#include "mlx5_core.h"
#include "fs_core.h"
#include "eswitch.h"

static int mlx5_devlink_flash_update(struct devlink *devlink,
				     const char *file_name,
				     const char *component,
				     struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	const struct firmware *fw;
	int err;

	if (component)
		return -EOPNOTSUPP;

	err = request_firmware_direct(&fw, file_name, &dev->pdev->dev);
	if (err)
		return err;

	return mlx5_firmware_flash(dev, fw, extack);
}

static u8 mlx5_fw_ver_major(u32 version)
{
	return (version >> 24) & 0xff;
}

static u8 mlx5_fw_ver_minor(u32 version)
{
	return (version >> 16) & 0xff;
}

static u16 mlx5_fw_ver_subminor(u32 version)
{
	return version & 0xffff;
}

#define DEVLINK_FW_STRING_LEN 32

static int
mlx5_devlink_info_get(struct devlink *devlink, struct devlink_info_req *req,
		      struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	char version_str[DEVLINK_FW_STRING_LEN];
	u32 running_fw, stored_fw;
	int err;

	err = devlink_info_driver_name_put(req, DRIVER_NAME);
	if (err)
		return err;

	err = devlink_info_version_fixed_put(req, "fw.psid", dev->board_id);
	if (err)
		return err;

	err = mlx5_fw_version_query(dev, &running_fw, &stored_fw);
	if (err)
		return err;

	snprintf(version_str, sizeof(version_str), "%d.%d.%04d",
		 mlx5_fw_ver_major(running_fw), mlx5_fw_ver_minor(running_fw),
		 mlx5_fw_ver_subminor(running_fw));
	err = devlink_info_version_running_put(req, "fw.version", version_str);
	if (err)
		return err;

	/* no pending version, return running (stored) version */
	if (stored_fw == 0)
		stored_fw = running_fw;

	snprintf(version_str, sizeof(version_str), "%d.%d.%04d",
		 mlx5_fw_ver_major(stored_fw), mlx5_fw_ver_minor(stored_fw),
		 mlx5_fw_ver_subminor(stored_fw));
	err = devlink_info_version_stored_put(req, "fw.version", version_str);
	if (err)
		return err;

	return 0;
}

static int mlx5_devlink_reload_down(struct devlink *devlink, bool netns_change,
				    struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	return mlx5_unload_one(dev, false);
}

static int mlx5_devlink_reload_up(struct devlink *devlink,
				  struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	return mlx5_load_one(dev, false);
}

#ifdef CONFIG_MLX5_ESWITCH

static int mlx5_devlink_rate_min_tx_set(struct devlink_slice_rate *devlink_slice_rate,
					int min_tx_rate, struct netlink_ext_ack *extack)
{
	if (devlink_slice_rate_is_leaf(devlink_slice_rate)) {
		struct mlx5_vport *vport = devlink_slice_rate_priv(devlink_slice_rate);

		return mlx5_eswitch_set_vport_min_rate(vport->dev->priv.eswitch,
						       vport->vport, min_tx_rate, extack);
	}

	return -EOPNOTSUPP;
}

static int mlx5_devlink_rate_min_tx_get(struct devlink_slice_rate *devlink_slice_rate,
					struct netlink_ext_ack *extack)
{
	if (devlink_slice_rate_is_leaf(devlink_slice_rate)) {
		struct mlx5_vport *vport = devlink_slice_rate_priv(devlink_slice_rate);
		struct ifla_vf_info ivi;
		int err;

		err = mlx5_eswitch_get_vport_config(vport->dev->priv.eswitch,
						    vport->vport, &ivi, extack);
		if (err)
			return err;
		return ivi.min_tx_rate;
	}

	return -EOPNOTSUPP;
}

static int mlx5_devlink_rate_max_tx_set(struct devlink_slice_rate *devlink_slice_rate,
					int max_tx_rate, struct netlink_ext_ack *extack)
{
	if (devlink_slice_rate_is_leaf(devlink_slice_rate)) {
		struct mlx5_vport *vport = devlink_slice_rate_priv(devlink_slice_rate);

		return mlx5_eswitch_set_vport_max_rate(vport->dev->priv.eswitch,
						       vport->vport, max_tx_rate,
						       extack);
	}

	return -EOPNOTSUPP;
}

static int mlx5_devlink_rate_max_tx_get(struct devlink_slice_rate *devlink_slice_rate,
					struct netlink_ext_ack *extack)
{
	if (devlink_slice_rate_is_leaf(devlink_slice_rate)) {
		struct mlx5_vport *vport = devlink_slice_rate_priv(devlink_slice_rate);
		struct ifla_vf_info ivi;
		int err;

		err = mlx5_eswitch_get_vport_config(vport->dev->priv.eswitch,
						    vport->vport, &ivi, extack);
		if (err)
			return err;
		return ivi.max_tx_rate;
	}

	return -EOPNOTSUPP;
}

static int mlx5_devlink_rate_node_new(struct devlink_slice_rate *slice_node,
				      struct netlink_ext_ack *extack)
{
	struct devlink *devlink = devlink_slice_rate_to_devlink(slice_node);
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5_vgroup *vgroup;

	vgroup = mlx5_eswitch_create_vgroup(esw, extack);
	if (IS_ERR(vgroup))
		return PTR_ERR(vgroup);

	devlink_slice_rate_set_priv(slice_node, vgroup, NULL);
	return 0;
}

static int mlx5_devlink_rate_node_del(struct devlink_slice_rate *slice_node,
				      struct netlink_ext_ack *extack)
{
	struct devlink *devlink = devlink_slice_rate_to_devlink(slice_node);
	struct mlx5_vgroup *vgroup = devlink_slice_rate_priv(slice_node);
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	struct mlx5_eswitch *esw = dev->priv.eswitch;

	return mlx5_eswitch_destroy_vgroup(esw, vgroup, extack);
}

#endif

static const struct devlink_ops mlx5_devlink_ops = {
#ifdef CONFIG_MLX5_ESWITCH
	.eswitch_mode_set = mlx5_devlink_eswitch_mode_set,
	.eswitch_mode_get = mlx5_devlink_eswitch_mode_get,
	.eswitch_inline_mode_set = mlx5_devlink_eswitch_inline_mode_set,
	.eswitch_inline_mode_get = mlx5_devlink_eswitch_inline_mode_get,
	.eswitch_encap_mode_set = mlx5_devlink_eswitch_encap_mode_set,
	.eswitch_encap_mode_get = mlx5_devlink_eswitch_encap_mode_get,
	.rate_min_tx_set = mlx5_devlink_rate_min_tx_set,
	.rate_min_tx_get = mlx5_devlink_rate_min_tx_get,
	.rate_max_tx_set = mlx5_devlink_rate_max_tx_set,
	.rate_max_tx_get = mlx5_devlink_rate_max_tx_get,
	.rate_node_new = mlx5_devlink_rate_node_new,
	.rate_node_del = mlx5_devlink_rate_node_del,
#endif
	.flash_update = mlx5_devlink_flash_update,
	.info_get = mlx5_devlink_info_get,
	.reload_down = mlx5_devlink_reload_down,
	.reload_up = mlx5_devlink_reload_up,
};

struct devlink *mlx5_devlink_alloc(void)
{
	return devlink_alloc(&mlx5_devlink_ops, sizeof(struct mlx5_core_dev));
}

void mlx5_devlink_free(struct devlink *devlink)
{
	devlink_free(devlink);
}

static int mlx5_devlink_fs_mode_validate(struct devlink *devlink, u32 id,
					 union devlink_param_value val,
					 struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	char *value = val.vstr;
	int err = 0;

	if (!strcmp(value, "dmfs")) {
		return 0;
	} else if (!strcmp(value, "smfs")) {
		u8 eswitch_mode;
		bool smfs_cap;

		eswitch_mode = mlx5_eswitch_mode(dev->priv.eswitch);
		smfs_cap = mlx5_fs_dr_is_supported(dev);

		if (!smfs_cap) {
			err = -EOPNOTSUPP;
			NL_SET_ERR_MSG_MOD(extack,
					   "Software managed steering is not supported by current device");
		}

		else if (eswitch_mode == MLX5_ESWITCH_OFFLOADS) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Software managed steering is not supported when eswitch offloads enabled.");
			err = -EOPNOTSUPP;
		}
	} else {
		NL_SET_ERR_MSG_MOD(extack,
				   "Bad parameter: supported values are [\"dmfs\", \"smfs\"]");
		err = -EINVAL;
	}

	return err;
}

static int mlx5_devlink_fs_mode_set(struct devlink *devlink, u32 id,
				    struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	enum mlx5_flow_steering_mode mode;

	if (!strcmp(ctx->val.vstr, "smfs"))
		mode = MLX5_FLOW_STEERING_MODE_SMFS;
	else
		mode = MLX5_FLOW_STEERING_MODE_DMFS;
	dev->priv.steering->mode = mode;

	return 0;
}

static int mlx5_devlink_fs_mode_get(struct devlink *devlink, u32 id,
				    struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	if (dev->priv.steering->mode == MLX5_FLOW_STEERING_MODE_SMFS)
		strcpy(ctx->val.vstr, "smfs");
	else
		strcpy(ctx->val.vstr, "dmfs");
	return 0;
}

enum mlx5_devlink_param_id {
	MLX5_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	MLX5_DEVLINK_PARAM_FLOW_STEERING_MODE,
};

static int mlx5_devlink_enable_roce_validate(struct devlink *devlink, u32 id,
					     union devlink_param_value val,
					     struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	bool new_state = val.vbool;

	if (new_state && !MLX5_CAP_GEN(dev, roce)) {
		NL_SET_ERR_MSG_MOD(extack, "Device doesn't support RoCE");
		return -EOPNOTSUPP;
	}

	return 0;
}

static const struct devlink_param mlx5_devlink_params[] = {
	DEVLINK_PARAM_DRIVER(MLX5_DEVLINK_PARAM_FLOW_STEERING_MODE,
			     "flow_steering_mode", DEVLINK_PARAM_TYPE_STRING,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     mlx5_devlink_fs_mode_get, mlx5_devlink_fs_mode_set,
			     mlx5_devlink_fs_mode_validate),
	DEVLINK_PARAM_GENERIC(ENABLE_ROCE, BIT(DEVLINK_PARAM_CMODE_DRIVERINIT),
			      NULL, NULL, mlx5_devlink_enable_roce_validate),
};

static void mlx5_devlink_set_params_init_values(struct devlink *devlink)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	union devlink_param_value value;

	if (dev->priv.steering->mode == MLX5_FLOW_STEERING_MODE_DMFS)
		strcpy(value.vstr, "dmfs");
	else
		strcpy(value.vstr, "smfs");
	devlink_param_driverinit_value_set(devlink,
					   MLX5_DEVLINK_PARAM_FLOW_STEERING_MODE,
					   value);

	value.vbool = MLX5_CAP_GEN(dev, roce);
	devlink_param_driverinit_value_set(devlink,
					   DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE,
					   value);
}

int mlx5_devlink_register(struct devlink *devlink, struct device *dev)
{
	int err;

	err = devlink_register(devlink, dev);
	if (err)
		return err;

	err = devlink_params_register(devlink, mlx5_devlink_params,
				      ARRAY_SIZE(mlx5_devlink_params));
	if (err)
		goto params_reg_err;
	mlx5_devlink_set_params_init_values(devlink);
	devlink_params_publish(devlink);
	devlink_reload_enable(devlink);
	return 0;

params_reg_err:
	devlink_unregister(devlink);
	return err;
}

void mlx5_devlink_unregister(struct devlink *devlink)
{
	devlink_reload_disable(devlink);
	devlink_params_unregister(devlink, mlx5_devlink_params,
				  ARRAY_SIZE(mlx5_devlink_params));
	devlink_unregister(devlink);
}

#ifdef CONFIG_MLX5_ESWITCH

static int
mlx5_devlink_mac_set(struct devlink_slice *devlink_slice, u8 *mac,
		     struct netlink_ext_ack *extack)
{
	struct mlx5_vport *vport = devlink_slice_priv(devlink_slice);

	return mlx5_eswitch_set_vport_mac(vport->dev->priv.eswitch,
					 vport->vport, mac, extack);
}

static int
mlx5_devlink_mac_get(struct devlink_slice *devlink_slice, u8 *mac,
		     struct netlink_ext_ack *extack)
{
	struct mlx5_vport *vport = devlink_slice_priv(devlink_slice);
	struct ifla_vf_info ivi;
	int err;

	vport = devlink_slice_priv(devlink_slice);

	err = mlx5_eswitch_get_vport_config(vport->dev->priv.eswitch,
					    vport->vport, &ivi, extack);
	if (!err)
		ether_addr_copy(mac, ivi.mac);

	return err;
}

static struct devlink_slice_ops slice_ops = {
	.hw_addr_set = mlx5_devlink_mac_set,
	.hw_addr_get = mlx5_devlink_mac_get,
	.hw_addr_len = ETH_ALEN,
};

int mlx5_devlink_slices_create(struct mlx5_eswitch *esw)
{
	struct devlink *devlink = priv_to_devlink(esw->dev);
	struct mlx5_vport *vport;
	int err;
	int i;

	mlx5_esw_for_all_vports(esw, i, vport) {
		struct devlink_slice_rate *devlink_rate;
		struct devlink_slice *devlink_slice;
		struct devlink_slice_attrs attrs;
		int slice_idx;

		if (IS_ERR(vport)) {
			err = PTR_ERR(vport);
			goto err_dl_destroy;
		}

		if (vport->vport == MLX5_VPORT_UPLINK ||
		    vport->vport == mlx5_eswitch_manager_vport(esw->dev))
			continue;

		slice_idx = vport->vport;
		if (mlx5_eswitch_is_vf_vport(esw, vport->vport))
			devlink_slice_attrs_pci_vf_init(&attrs, 0,
							slice_idx - 1);
		else if (vport->vport == MLX5_VPORT_PF)
			devlink_slice_attrs_pci_pf_init(&attrs, slice_idx);

		devlink_slice = devlink_slice_create(devlink, slice_idx,
						     &slice_ops, &attrs,
						     vport);
		if (IS_ERR(devlink_slice)) {
			err = PTR_ERR(devlink_slice);
			goto err_dl_destroy;
		}
		vport->devlink_slice = devlink_slice;

		if (mlx5_eswitch_is_vf_vport(esw, vport->vport)) {
			devlink_rate = devlink_slice_rate_leaf_create(devlink_slice,
								      vport);
			if (IS_ERR(devlink_rate)) {
				err = PTR_ERR(devlink_rate);
				goto err_dl_destroy;
			}
			vport->devlink_rate = devlink_rate;
		}
	}

	return 0;

err_dl_destroy:
	mlx5_devlink_slices_destroy(esw);
	return err;
}

static void mlx5_devlink_rate_node_cleanup(struct mlx5_eswitch *esw)
{
	struct devlink *devlink = priv_to_devlink(esw->dev);

	mlx5_eswitch_cleanup_vgroups(esw);
	devlink_slice_rate_node_destroy_all(devlink);
}

void mlx5_devlink_slices_destroy(struct mlx5_eswitch *esw)
{
	struct mlx5_vport *vport;
	int i;

	mlx5_esw_for_all_vports_reverse(esw, i, vport) {
		if (vport->devlink_rate)
			devlink_slice_rate_leaf_destroy(vport->devlink_rate);
		if (vport->devlink_slice)
			devlink_slice_destroy(vport->devlink_slice);
	}
	mlx5_devlink_rate_node_cleanup(esw);
}

#endif /* CONFIG_MLX5_ESWITCH */
