.. SPDX-License-Identifier: GPL-2.0

==============
Devlink Slice
==============

Introduction
============
The network ASIC may expose privileged and non-privileged (slice) devices.
A privileged user can control the parameters of the slice through the
privileged device.

The network ASIC exposes PCI PF and SR-IOV VF device(s) to the host system
where it is connected as PCIe end point. An administrator needs to manage
attributes and resource of such PCI PF/VF such as MAC address, MSI-X vectors
etc. in the ASIC.

An administrator doesn't have access to the host system where the PCIe ASIC
device is connected. In some use cases host system may not even be running Linux
kernel where the PCIe PF and VF devices are enumerated.
Currently, the networking ASIC exposes devlink interfaces for eswitch
mamangement. However, there is no user interface to manage attributes and
resources on the ASIC device.

Additionally, the PCIe PF and VF devices may be of a different class
than networking; such as NVMe, GPU, crypto or something else.
For non-networking devices, there may not be any eswitch (eswitch ports).

It is desirable to control common PCIe attributes and resources through
common kernel infrastructure. Some of the attributes or resources may not be a
port parameter, i.e. number of IRQ (MSI-X) vectors per PF/VF.

An example system view of a networking ASIC (aka SmartNIC), can be seen in the
below diagram, where devlink eswitch instance and PCI PF and/or VFs are
situated on two different CPU subsystems::


	  +------------------------------+
	  |                              |
	  |             HOST             |
	  |                              |
	  |   +----+-----+-----+-----+   |
	  |   | PF | VF0 | VF1 | VF2 |   |
	  +---+----+-----------+-----+---+
        	     PCI1|
	      +---+------------+
        	  |
	 +----------------------------------------+
	 |        |         SmartNic              |
	 |   +----+-------------------------+     |
	 |   |                              |     |
	 |   |               NIC            |     |
	 |   |                              |     |
	 |   +---------------------+--------+     |
	 |                         |  PCI2        |
	 |         +-----+---------+--+           |
	 |               |                        |
	 |      +-----+--+--+--------------+      |
	 |      |     | PF  |              |      |
	 |      |     +-----+              |      |
	 |      |      Embedded CPU        |      |
	 |      |                          |      |
	 |      +--------------------------+      |
	 |                                        |
	 +----------------------------------------+

The below diagram shows an example of devlink slice topology where some
slices are connected to devlink ports::



            (PF0)    (VF0)    (VF1)           (NVME VF2)
         +--------------------------+         +--------+
         | devlink| devlink| devlink|         | devlink|
         | slice | slice | slice |         | slice |
         |    0   |    1   |    2   |         |    3   |
         +--------------------------+         +--------+
              |        |        |
              |        |        |
              |        |        |
     +----------------------------------+
     |   | devlink| devlink| devlink|   |
     |   |  port  |  port  |  port  |   |
     |   |    0   |    1   |    2   |   |
     |   +--------------------------+   |
     |                                  |
     |                                  |
     |           E-switch               |
     |                                  |
     |                                  |
     |          +--------+              |
     |          | uplink |              |
     |          | devlink|              |
     |          |  port  |              |
     +----------------------------------+


.. _Slice-Flavours:

Slice flavours
===============

The ``devlink-slice`` supports the following device flavours:

  * ``pcipf``: exposes pf_index attribute.
  * ``pcivf``: exposes vf_index and pf_index.

.. _Slice-Actions:

Network attributes:
==================

The ``devlink-slice`` may represent a network device and expose the following
attributes:

  * ``hw_addr``: The HW addr of the network device.
  * ``port_index``: The ``devlink-port`` index associated with the device.

Testing
=======

See ``tools/testing/selftests/drivers/net/netdevsim/devlink.sh`` for a
test covering the core infrastructure. Test cases should be added for any new
functionality.

