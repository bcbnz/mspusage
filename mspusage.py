#!/usr/bin/env python

# mspusage - Python script to calculate flash and RAM usage of
#            an MSP430 binary.
#
# Written in 2012 by Blair Bonnett
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related and neighboring rights to this software to the public domain
# worldwide. This software is distributed without any warranty.  You should have
# received a copy of the CC0 Public Domain Dedication along with this software.
# If not, see <http://creativecommons.org/publicdomain/zero/1.0/>

import argparse
import re
import sys
import subprocess

# Parse command-line arguments.
parser = argparse.ArgumentParser(description='Calculate the flash and RAM usage of an MSP430 ELF binary.')
parser.add_argument('binary', help='The ELF file to calculate the usage from.')
parser.add_argument('--verbose', '-v', action='count',
                    help="If given once, also prints out details of the "
                    "objects stored in flash and RAM, and the vector table. "
                    "If given twice, also prints out the call chains for the "
                    "functions."
                   )
parser.add_argument('--quiet', '-q', action='store_true', default=False,
                    help="Print out the total flash available, and the amounts "
                    "used and free separated by spaces on the first line, and "
                    "the same details for RAM on the second line. Overrides "
                    "the --verbose option."
                   )
parser.add_argument('--function-pointer', '-p', action='append',
                    metavar="function_name=<pattern>",
                    help="To accurately track stack usage, we need to follow "
                    "any function pointers. These must be specified on the "
                    "command line in the format function_name=<pattern>, where "
                    "<pattern> is a regular expression matching any functions "
                    "that are called via pointers. For example, -p "
                    "spi_rx=spi_handle_.+ tells the script that the function "
                    "spi_rx() can call any function starting with spi_handle_ "
                    "via function pointers."
                   )
args = parser.parse_args()

# Post-process the quiet and verbose arguments.
if args.quiet:
    args.verbose = 0
elif args.verbose is None:
    args.verbose = 1
else:
    args.verbose += 1

# Some regular expressions to match different components.
section_re = re.compile('^(?P<addr>[0-9A-Fa-f]{8})\s+<(?P<name>.+?)>:\s*$')
instr_re = re.compile('^\s*(?P<addr>[0-9A-Fa-f]{4,8}):\s+(?P<codes>[0-9A-Fa-f ]+)\t?(?P<asm>.+?)?(?:;.+)?$')

# Get the symbol table from objdump.
proc = subprocess.Popen(['msp430-objdump', '-t', args.binary], stdout=subprocess.PIPE)
stdout, stderr = proc.communicate()
symtab = stdout.splitlines()

ramvars = {}
ramend = None
ramstart = None
ramvar_size = 0

functions = {
    -1: {
        'name': 'unknown_function_pointer',
        'size': 0,
        'local_stack': 1000000,
        'max_call_stack': 0,
        'max_stack': 0,
        'call_addresses': set(),
        'called_by': set(),
        'calls': [],
        'function_pointers': []
    }
}
tables = {}

flash_end = None
flash_start = None
flash_used = None

main_address = None

vectors = {}

unexpected = None
reset = None

# Process the symbol table.
for line in symtab:
    if not line.strip() or not line[0].isdigit():
        continue

    # Split into its pieces.
    value, line = line.split(' ', 1)
    flags, section, size, name = line.rsplit(None, 3)

    # Format the pieces.
    value = int(value, 16)
    flags = set(c for c in flags if c.isalpha())
    section = section.strip().lower()
    size = int(size, 16)
    name = name.strip()

    # Sections relating to RAM usage.
    if section in ('.bss', '.data', '*abs*'):
        # Non-zero size ==> variable.
        if size != 0:
            ramvars[value] = {'name': name, 'size': size,
                                'initialised': section.lower() == '.data'}
            ramvar_size += size

        # Details about RAM size.
        elif name.lower() == '__data_start':
            ramend = value
        elif name.lower() == '__stack':
            ramstart = value

    # Code section.
    elif section in ('.text'):
        # Function.
        if 'F' in flags:
            functions[value] = {
                'name': name,
                'size': size,
                'local_stack': 0,
                'max_call_stack': 0,
                'max_stack': 0,
                'call_addresses': set(),
                'called_by': set(),
                'calls': [],
                'function_pointers': []
            }
            if name == 'main':
                main_address = value

        # Table.
        elif 'O' in flags:
            tables[value] = {'name': name, 'size': size}

        # Start of the flash section.
        elif name == '.text':
            flash_start = value

        # Address used for unhandled interrupt vectors.
        elif name == '__br_unexpected_':
            unexpected = value

        # End of the code.
        elif name == '_unexpected_':
            flash_used = value + 2

        # Where the reset vector is pointed to.
        elif name == '_reset_vector__':
            reset = value

        # Where the various interrupt vectors are pointed to.
        elif name[:6] == '__isr_':
            vectors[int(name[6:])] = value

    # Vector section: only used as a marker for the end of flash.
    elif section in ('.vectors'):
        if name == '_vectors_end':
            flash_end = value

# Store any function pointers we were told about.
for pointer in args.function_pointer or []:
    try:
        name, pattern = pointer.split('=', 1)
    except ValueError:
        raise SystemExit("Function pointer arguments must be in the format function=pattern")

    if pattern[0] != '^':
        pattern = '^' + pattern
    if pattern[-1] != '$':
        pattern = pattern + '$'
    try:
        pattern = re.compile(pattern)
    except re.error:
        raise SystemExit("Function pointer pattern '{0:s}' is invalid.".format(called))

    func_address = None
    for address, details in functions.items():
        if details['name'] == name:
            func_address, func_details = address, details
            break
    if func_address is None:
        raise SystemExit("Unknown function {0:s}.".format(name))

    calls = []
    for address, details in functions.items():
        if address != func_address and pattern.match(details['name']):
            calls.append(address)
    if not calls:
        sys.stderr.write("WARNING: No functions match function pointer pattern {0:s}\n".format(pattern.pattern))
    func_details['function_pointers'] = calls

# Now use objdump to disassemble the code.
proc = subprocess.Popen(['msp430-objdump', '-d', '-j', '.text', args.binary],
                           stdout=subprocess.PIPE)
stdout, stderr = proc.communicate()
objdump = iter(stdout.splitlines())

# Process the disassembly.
for line in objdump:
    # Find the next section.
    section = section_re.match(line)
    if not section:
        continue

    # See if it is a function.
    d = section.groupdict()
    addr = int(d['addr'], 16)
    if addr not in functions:
        continue

    # Pull out our current details and add some initial values.
    details = functions[addr]

    # Keep going until we've seen the appropriate number of bytes of code.
    seen = 0
    while seen < details['size']:
        # Split up the disassembly line.
        instr = instr_re.match(next(objdump)).groupdict()
        seen += len(instr['codes'].split())

        # Look for the mnemonic of the instruction.
        if instr['asm']:
            pieces = instr['asm'].split()
            mnemonic = pieces[0].lower()

            # Pushing a word onto the stack ==> two more bytes used.
            if mnemonic == 'push':
                details['local_stack'] += 2

            # Calling a function. 2 bytes of stack are used for the function
            # pointer.
            elif mnemonic == 'call':
                details['local_stack'] += 2
                call_addr = pieces[1].lower()

                # Calling an absolute address.
                if call_addr[:3] == '#0x':
                    tocall = int(call_addr[3:], 16)
                    details['call_addresses'].add(tocall)
                    functions[tocall]['called_by'].add(addr)

                # Calling a function pointer stored in a register or memory
                # location.
                elif call_addr[0] in ('r', '&'):
                    if details['function_pointers']:
                        details['call_addresses'].update(details['function_pointers'])
                    else:
                        details['call_addresses'].add(-1)
                        functions[-1]['called_by'].add(addr)

                # Unknown call argument.
                else:
                    raise SystemExit("Unhandled call argument: {0:s}".format(call_addr))

# Calculate the call chains for a function.
# Call chain: [(addr, size), (addr, size), ..., (addr, size)]
def calculate_call_chain(addr):
    # Already done.
    if 'call_addresses' not in functions[addr]:
        return

    # Go through the addresses of called functions.
    for called in functions[addr]['call_addresses']:
        # Make sure their call chains have been calculated.
        calculate_call_chain(called)

        # Prepare the entry for the called function.
        entry = (called, functions[called]['local_stack'])

        # If the called function calls other functions itself, prepend the entry
        # to each of the existing child chains.
        if functions[called]['calls']:
            for chain in functions[called]['calls']:
                newchain = list(chain)
                newchain.insert(0, entry)
                functions[addr]['calls'].append(newchain)

        # End of the line, just add the called function.
        else:
            functions[addr]['calls'].append([entry])

    # Finished.
    del functions[addr]['call_addresses']

# Try to resolve the calls to calculate stack depths.
for address in functions.keys():
    # Make sure the call chain has been determined.
    calculate_call_chain(address)
    details = functions[address]

    # Find the maximum stack usage from a call chain.
    for chain in details['calls']:
        size = 0
        for call in chain:
            size += call[1]
        if size > details['max_call_stack']:
            details['max_call_stack'] = size

    # Calculate maximum possible stack.
    details['max_stack'] = details['local_stack'] + details['max_call_stack']

# Print details of RAM contents.
if args.verbose > 1:
    sys.stdout.write('\nVariables in RAM:\n-----------------\n\n')
    for addr, details in sorted(ramvars.items()):
        sys.stdout.write('0x{0:X}: {1:s} ({2:d} byte{3:s})\n'.format(addr,
                                                                     details['name'],
                                                                     details['size'],
                                                                    '' if details['size'] == 1 else 's'))
# Print details of flash contents.
if args.verbose > 1:
    functions.update(tables)
    sys.stdout.write('\nObjects in flash:\n-----------------\n')
    for addr, details in sorted(functions.items()):
        if addr == -1:
            continue

        # Function address and name.
        sys.stdout.write('\n0x{0:04X}: {1:s}'.format(addr, details['name']))

        # Size and plural as appropriate.
        size = (details['size'], '' if details['size'] == 1 else 's')

        # This is a function.
        if 'calls' in details:
            # Size and stack usage.
            sys.stdout.write('()\n        Function of {0:d} byte{1:s}\n'.format(*size))
            local = (details['local_stack'], '' if details['local_stack'] == 1 else 's')
            sys.stdout.write('        Local stack: {0:d} byte{1:s}\n'.format(*local))

            # Stack size of called functions, if any.
            call = (details['max_call_stack'], '' if details['max_call_stack'] == 1 else 's')
            if details['calls']:
                sys.stdout.write('        Maximum stack used by called functions: {0:d} byte{1:s}\n'.format(*call))
            else:
                sys.stdout.write('        Maximum stack used by called functions: N/A\n')

            # Print the call chains of this function.
            if args.verbose > 2:
                if details['calls']:
                    sys.stdout.write('\n        Calls:\n        ------\n')
                for chain in details['calls']:
                    sys.stdout.write('        ')
                    sys.stdout.write(' -> '.join(functions[call[0]]['name'] + "()" for call in chain))
                    call_size = sum(call[1] for call in chain)
                    sys.stdout.write(' ({0:d} bytes of stack)\n'.format(call_size))

        # This is a data table.
        else:
            sys.stdout.write('\n        Data table of {0:d} byte{1:s}\n'.format(*size))

# Print out vector information.
if args.verbose > 1:
    sys.stdout.write('\nVector table:\n-------------\n\n')
    for vector, address in sorted(vectors.items()):
        sys.stdout.write('Interrupt vector {0:2d}: '.format(vector))
        if address == unexpected:
            sys.stdout.write('unused\n')
        else:
            sys.stdout.write('{0:s} (0x{1:X})\n'.format(functions[address]['name'], address))

# Print flash statistics.
flash_total = flash_end - flash_start
flash_used = flash_used - flash_start
flash_free = flash_total - flash_used
if args.verbose == 0:
    sys.stdout.write('{0:d} {1:d} {2:d}\n'.format(flash_total, flash_used, flash_free))
else:
    if args.verbose > 1:
        sys.stdout.write('\nUsage statistics:\n-----------------\n\n')
    sys.stdout.write('Flash size: {0:d} bytes\n'.format(flash_total))
    sys.stdout.write('Used: {0:d} bytes ({1:.2f}%)\n'.format(flash_used, flash_used*100.0/flash_total))
    sys.stdout.write('Free: {0:d} bytes ({1:.2f}%)\n'.format(flash_free, flash_free*100.0/flash_total))

# Calculate the maximum stack used by an ISR.
max_vector = 0
for vector, address in sorted(vectors.items()):
    if address != unexpected and functions[address]['max_stack'] > max_vector:
        max_vector = functions[address]['max_stack']

# Print RAM statistics.
ram_total = ramstart - ramend
main_stack = functions[main_address]['max_stack']
ram_used = ramvar_size + main_stack + max_vector
ram_free = ram_total - ram_used
if args.verbose == 0:
    sys.stdout.write('{0:d} {1:d} {2:d}\n'.format(ram_total, ram_used, ram_free))
else:
    sys.stdout.write('\n')
    sys.stdout.write('RAM size: {0:d} bytes\n'.format(ram_total))
    sys.stdout.write('Used by variables: {0:d} bytes ({1:.2f}%)\n'.format(ramvar_size, ramvar_size*100.0/ram_total))
    sys.stdout.write('Used by main stack: {0:d} bytes ({1:.2f}%)\n'.format(main_stack, main_stack*100.0/ram_total))
    sys.stdout.write('Used by maximum ISR stack: {0:d} bytes ({1:.2f}%)\n'.format(max_vector, max_vector*100.0/ram_total))
    sys.stdout.write('Unused: {0:d} bytes ({1:.2f}%)\n'.format(ram_free, ram_free*100.0/ram_total))

# Unknown function pointers were called.
if functions[-1]['called_by']:
    sys.stderr.write('\nThe following function(s) called unknown function pointers:\n* ')
    sys.stderr.write('\n* '.join(functions[a]['name'] for a in functions[-1]['called_by']))
    sys.stderr.write('\n\nTheir stack usage has been set to 1MB since a value cannot be accurately determined.\n')
    sys.stderr.write('Please specify the functions they call using the --function-pointer argument.\n')
