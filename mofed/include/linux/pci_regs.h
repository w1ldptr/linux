#ifndef _COMPAT_LINUX_PCI_REGS_H
#define _COMPAT_LINUX_PCI_REGS_H

#include "../../compat/config.h"

#include_next <linux/pci_regs.h>


#ifndef PCI_EXP_LNKCAP_SLS_2_5GB
#define  PCI_EXP_LNKCAP_SLS_2_5GB 0x00000001 /* LNKCAP2 SLS Vector bit 0 */
#endif

#ifndef PCI_EXP_LNKCAP_SLS_5_0GB
#define  PCI_EXP_LNKCAP_SLS_5_0GB 0x00000002 /* LNKCAP2 SLS Vector bit 1 */
#endif

#ifndef PCI_EXP_LNKCAP_SLS_8_0GB
#define  PCI_EXP_LNKCAP_SLS_8_0GB 0x00000003 /* LNKCAP2 SLS Vector bit 2 */
#endif

#ifndef PCI_EXP_LNKCAP2_SLS_16_0GB
#define PCI_EXP_LNKCAP2_SLS_16_0GB	0x00000010 /* Supported Speed 16GT/s */
#define PCIE_SPEED_16_0GT		0x17
#define PCI_EXP_LNKCAP_SLS_16_0GB	0x00000004 /* LNKCAP2 SLS Vector bit 3 */
#endif

#endif /* _COMPAT_LINUX_PCI_REGS_H */
