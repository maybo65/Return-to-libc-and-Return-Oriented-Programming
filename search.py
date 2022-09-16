import addresses
from infosec.core import assemble
from typing import Tuple, Iterable
import string


GENERAL_REGISTERS = [
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'
]


ALL_REGISTERS = GENERAL_REGISTERS + [
    'esp', 'eip', 'ebp'
]


class GadgetSearch(object):
    def __init__(self, dump_path: str, start_addr=None):
        """
        Construct the GadgetSearch object.

        Input:
            dump_path: The path to the memory dump file created with GDB.
            start_addr: The starting memory address of this dump. Use
                        `addresses.LIBC_TEXT_START` by default.
        """
        self.start_addr = (start_addr if start_addr is not None
                           else addresses.LIBC_TEXT_START)
        with open(dump_path, 'rb') as f:
            self.dump = f.read()

    def get_format_count(self, gadget_format: str) -> int:
        """
        Get how many different register placeholders are in the pattern.

        Examples:
            self.get_format_count('POP ebx')
            => 0
            self.get_format_count('POP {0}')
            => 1
            self.get_format_count('XOR {0}, {0}; ADD {0}, {1}')
            => 2
        """
        # Hint: Use the string.Formatter().parse method:
        #
        #   import string
        #   print string.Formatter().parse(gadget_format)
        #this will get the len of a list containing each uniqe placeholder. the set if for the uniqness. 
        return len(set([x[1] for x in string.Formatter().parse(gadget_format)]))


    def get_register_combos_rec(self,nregs: int, registers: Tuple[str]):
        # a recursive function that will get all the possible combos to the given registers, in list from size of nregs
        if nregs == 1:
            #base case
            return [[reg] for reg in registers]
        else:
            #recursive call
            X = self.get_register_combos_rec(nregs - 1, registers)
            register_combos = []
            # adding each option to the first register on a list from size nregs, with all the possible we got from calling the fucntion with nargs-1
            for i in range(nregs):
                register_combos += [ [registers[i] ] + x for x in X]
            return register_combos
        
    def get_register_combos(self, nregs: int, registers: Tuple[str]) -> Iterable[Iterable[str]]:
        """
        Return all the combinations of `registers` with `nregs` registers in
        each combination. Duplicates ARE allowed!

        Example:
            self.get_register_combos(2, ('eax', 'ebx'))
            => [['eax', 'eax'],
                ['eax', 'ebx'],
                ['ebx', 'eax'],
                ['ebx', 'ebx']]
        """
        #special edge case
        if (nregs==0 or (len(registers)==0)):
            return []
        else:
        #call the recursive function
            return self.get_register_combos_rec(nregs, list(registers))
        

    def format_all_gadgets(self, gadget_format: str, registers: Tuple[str]) -> Iterable[str]:
        """
        Format all the possible gadgets for this format with the given
        registers.

        Example:
            self.format_all_gadgets("POP {0}; ADD {0}, {1}", ('eax', 'ecx'))
            => ['POP eax; ADD eax, eax',
                'POP eax; ADD eax, ecx',
                'POP ecx; ADD ecx, eax',
                'POP ecx; ADD ecx, ecx']
        """
        # Hints:
        #
        # 0. Use the previous functions to count the number of placeholders,
        #    and get all combinations of registers.
        #
        # 1. Use the `format` function to build the string:
        #
        #    'Hi {0}! I am {1}, you are {0}'.format('Luke', 'Vader')
        #    => 'Hi Luke! I am Vader, you are Luke'
        #
        # 2. You can pass a list of arguments instead of specifying each
        #    argument individually. Use the internet, the force is strong with
        #    StackOverflow.
        #calcule the number of registers we can use        
        nregs = self.get_format_count(gadget_format)
        # if zero, this is a gadget with no placeholders
        if nregs == 0:
            return gadget_format
        gadgets = []
        # get all the combos to the given registers from size nregs
        register_combos = self.get_register_combos_rec(nregs, registers)
        for combo in register_combos:
            #for each combination of registers, place them instead of the placeholders in the gadget and add that
            gadgets.append(gadget_format.format(*combo))
        return gadgets
        
    def find_all(self, gadget: str) -> Iterable[int]:
        """
        Return all the addresses of the gadget inside the memory dump.

        Example:
            self.find_all('POP eax')
            => < all ABSOLUTE addresses in memory of 'POP eax; RET' >
        """
        # Notes:
        #
        # 1. Addresses are ABSOLUTE (for example, 0x08403214), NOT RELATIVE to
        #    the beginning of the file (for example, 12).
        #
        # 2. Don't forget to add the 'RET'.
        #adding ret as next opcode
        gadget_to_find = assemble.assemble_data(gadget + "; ret")
        #get all the indices of this gadget
        offsets_indices = [i for i in range(len(self.dump)) if self.dump.startswith(gadget_to_find, i)]
        #return the actual addresses using the indices and the address of the start of the file
        return [self.start_addr + i for i in offsets_indices]

    def find(self, gadget: str, condition=None) -> int:
        """
        Return the first result of find_all. If condition is specified, only
        consider addresses that meet the condition.
        """
        condition = condition or (lambda x: True)
        try:
            return next(addr for addr in self.find_all(gadget)
                        if condition(addr))
        except StopIteration:
            raise ValueError("Couldn't find matching address for " + gadget)

    def find_all_formats(self, gadget_format: str,
                         registers: Iterable[str] = GENERAL_REGISTERS) -> Iterable[Tuple[str, int]]:
        """
        Similar to find_all - but return all the addresses of all
        possible gadgets that can be created with this format and registers.
        Every element in the result will be a tuple of the gadget string and
        the address in which it appears.

        Example:
            self.find_all_formats('POP {0}; POP {1}')
            => [('POP eax; POP ebx', address1),
                ('POP ecx; POP esi', address2),
                ...]
        """
        # create a list of all the possible gadget with this format and those registers
        gadgets = self.format_all_gadgets(gadget_format, registers)
        x=[]
        #for every gadget, fjng all the addresses of this gadget in the file and add them to x 
        for gadget in gadgets:
            address_per_gadget = self.find_all(gadget)
            x += [[gadget, address] for address in address_per_gadget]
        return x

    def find_format(self, gadget_format: str,
                    registers: Iterable[str] = GENERAL_REGISTERS,
                    condition=None) -> Tuple[str, int]:
        """
        Return the first result of find_all_formats. If condition is specified,
        only consider gadget-address tuples that meet the condition.
        """
        condition = condition or (lambda x: True)
        try:
            return next(
                gadget_addr for gadget_addr in self.find_all_formats(gadget_format, registers)
                if condition(gadget_addr)
            )
        except StopIteration:
            raise ValueError(
                "Couldn't find matching address for " + gadget_format)
