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

    /* this is the VM that we are looking at */
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
