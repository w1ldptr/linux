/*
 * rh_wrap.c - RHEL specific wrappers
 */

#include <linux/netdevice.h>
#include <net/pkt_cls.h>

int __rh_call_ndo_setup_tc(struct net_device *dev, enum tc_setup_type type,
			   void *type_data)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if (get_ndo_ext(ops, ndo_setup_tc_rh)) {
		return get_ndo_ext(ops, ndo_setup_tc_rh)(dev, type, type_data);
	}

	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(__rh_call_ndo_setup_tc);
