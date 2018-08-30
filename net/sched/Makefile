#
# Makefile for the Linux Traffic Control Unit.
#

obj-y	:= sch_generic.o sch_mq.o

obj-$(CONFIG_NET_SCHED)		+= sch_api.o sch_blackhole.o
obj-$(CONFIG_NET_CLS)		+= cls_api.o
obj-$(CONFIG_NET_CLS_ACT)	+= act_api.o
obj-$(CONFIG_NET_ACT_POLICE)	+= act_police.o
obj-$(CONFIG_NET_ACT_GACT)	+= act_gact.o
obj-$(CONFIG_NET_ACT_MIRRED)	+= act_mirred.o
obj-$(CONFIG_NET_ACT_SAMPLE)	+= act_sample.o
obj-$(CONFIG_NET_ACT_IPT)	+= act_ipt.o
obj-$(CONFIG_NET_ACT_NAT)	+= act_nat.o
obj-$(CONFIG_NET_ACT_PEDIT)	+= act_pedit.o
obj-$(CONFIG_NET_ACT_SIMP)	+= act_simple.o
obj-$(CONFIG_NET_ACT_SKBEDIT)	+= act_skbedit.o
obj-$(CONFIG_NET_ACT_CSUM)	+= act_csum.o
obj-$(CONFIG_NET_ACT_VLAN)	+= act_vlan.o
obj-$(CONFIG_NET_ACT_CONNMARK)	+= act_connmark.o
obj-$(CONFIG_NET_ACT_SKBMOD)	+= act_skbmod.o
obj-$(CONFIG_NET_ACT_IFE)	+= act_ife.o
obj-$(CONFIG_NET_IFE_SKBMARK)	+= act_meta_mark.o
obj-$(CONFIG_NET_IFE_SKBPRIO)	+= act_meta_skbprio.o
obj-$(CONFIG_NET_IFE_SKBTCINDEX)	+= act_meta_skbtcindex.o
obj-$(CONFIG_NET_ACT_TUNNEL_KEY)+= act_tunnel_key.o

obj-$(CONFIG_NET_SCH_FIFO)	+= sch_fifo.o
obj-$(CONFIG_NET_SCH_INGRESS)	+= sch_ingress.o 

obj-$(CONFIG_NET_CLS_U32)	+= cls_u32.o
obj-$(CONFIG_NET_CLS_ROUTE4)	+= cls_route.o
obj-$(CONFIG_NET_CLS_FW)	+= cls_fw.o
obj-$(CONFIG_NET_CLS_RSVP)	+= cls_rsvp.o
obj-$(CONFIG_NET_CLS_TCINDEX)	+= cls_tcindex.o
obj-$(CONFIG_NET_CLS_RSVP6)	+= cls_rsvp6.o
obj-$(CONFIG_NET_CLS_BASIC)	+= cls_basic.o
obj-$(CONFIG_NET_CLS_FLOW)	+= cls_flow.o
obj-$(CONFIG_NET_CLS_CGROUP)	+= cls_cgroup.o
obj-$(CONFIG_NET_CLS_BPF)	+= cls_bpf.o
obj-$(CONFIG_NET_CLS_FLOWER)	+= cls_flower.o
obj-$(CONFIG_NET_CLS_MATCHALL)	+= cls_matchall.o

obj-y += rh_kabi.o
