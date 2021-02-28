/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>

#include <libvmi/libvmi.h>
#include <libvmi/slat.h>

int main (int argc, char **argv)
{
    vmi_instance_t vmi;

    /* this is the VM or file that we are looking at */
    if (argc != 2) {
        printf("Usage: %s <vmname>\n", argv[0]);
        return 1;
    } // if

    char *name = argv[1];

    /* initialize the libvmi library */
    if (VMI_FAILURE ==
            vmi_init(&vmi, VMI_XEN, name, VMI_INIT_DOMAINNAME, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    if (VMI_FAILURE == vmi_slat_set_domain_state(vmi, true)) {
        printf("Failed get domain SLAT state.\n");
	return 1;
    }

    /* cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);

    printf("Succesfully enabled SLAT\n");
    return 0;
}
