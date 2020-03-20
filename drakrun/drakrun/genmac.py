import sys
import random


def gen_mac(vm_id):
    rnd = random.Random()
    rnd.seed(vm_id)
    return [0x00, 0x16, 0x3e, rnd.randint(0x00, 0x7f), rnd.randint(0x00, 0xff), rnd.randint(0x00, 0xff)]


def print_mac(mac):
    return ':'.join(map(lambda x: "%02x" % x, mac))


if __name__ == "__main__":
    print(print_mac(gen_mac(int(sys.argv[1]))), end='')
