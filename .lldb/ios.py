import lldb
import shlex
import optparse
import struct


#############################################################################
# GUI                                                                       #
#############################################################################


def Red(output):
    return Color(31, output)

def Blue(output):
    return Color(34, output)

def Green(output):
    return Color(32, output)

def Yellow(output):
    return Color(33, output)

def Color(color, output):
    return("\033[{0}m{1}\033[0m".format(color, output))


#############################################################################
# Registers                                                                 #
#############################################################################


def get_registers(debugger):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetFrameAtIndex(0)

    registerSet = frame.GetRegisters()
    for regs in registerSet:
        if 'general purpose registers' in regs.GetName().lower():
            GPRs = regs
            break

    regs = {}
    for reg in GPRs:
        regs[reg.GetName()] = reg.GetValue()

    return regs


def show_registers(debugger, command, result, internal_dict):
    regs = get_registers(debugger)

    print("-" * 67)
    r0 = "{0}: {1}".format(Green("R00"), regs["r0"])
    r1 = "{0}: {1}".format(Green("R01"), regs["r1"])
    r2 = "{0}: {1}".format(Green("R02"), regs["r2"])
    r3 = "{0}: {1}".format(Green("R03"), regs["r3"])
    print("[ {0} {1} {2} {3} ]".format(r0, r1, r2, r3))

    r4 = "{0}: {1}".format(Green("R04"), regs["r4"])
    r5 = "{0}: {1}".format(Green("R05"), regs["r5"])
    r6 = "{0}: {1}".format(Green("R06"), regs["r6"])
    r7 = "{0}: {1}".format(Green("R07"), regs["r7"])
    print("[ {0} {1} {2} {3} ]".format(r4, r5, r6, r7))

    r8 = "{0}: {1}".format(Green("R08"), regs["r8"])
    r9 = "{0}: {1}".format(Green("R09"), regs["r9"])
    r10 = "{0}: {1}".format(Green("R10"), regs["r10"])
    r11 = "{0}: {1}".format(Green("R11"), regs["r11"])
    print("[ {0} {1} {2} {3} ]".format(r8, r9, r10, r11))

    r12 = "{0}: {1}".format(Green("R12"), regs["r12"])
    sp = "{0}: {1}".format(Blue("*SP"), regs["sp"])
    lr = "{0}: {1}".format(Blue("*LR"), regs["lr"])
    pc = "{0}: {1}".format(Red("*PC"), regs["pc"])
    print("[ {0} {1} {2} {3} ]".format(r12, sp, lr, pc))

    print("\033[33m")
    debugger.HandleCommand('disassemble --arch thumb -p')
    print("\033[0m" + "-" * 67)


#############################################################################
# Hexdump                                                                   #
#############################################################################

arch_format = "08X"
arch_size = 4


def decode_address(debugger, arg):
    address = 0
    if arg[0] == "$":
        regs = get_registers(debugger)
        if arg[1:] in regs:
            address = regs[arg[1:]]
    else:
        address = arg

    return int(address, 0)


def hexdump(data, offset, size=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    offset = offset

    while data:
        chunk, data = data[:size], data[size:]
        output = ""
  
        output += Blue("0x{0:{1}}  ".format(offset, arch_format))

        chunk1, chunk2 = chunk[:size//2], chunk[size//2:]
        output += " ".join(["%02x" % ord(x) for x in chunk1])
        output += "  "
        output += " ".join(["%02x" % ord(x) for x in chunk2])
        output += "  " + " " * (((size-len(chunk))*3)-1)

        output += Yellow("".join(["%c" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chunk]))

        print(output)
        offset += len(chunk)


def show_hexdump(debugger, command, result, internal_dict):
    command_args = shlex.split(command)
    #print(command_args)

    usage = "usage: xd address [size]"
    description='''Print a hexdump of the selected memory.'''
    parser = optparse.OptionParser(description=description, prog='xd', usage=usage)

    try:
        (options, args) = parser.parse_args(command_args)
    except:
        return

    if len(args) < 1:
        print(usage)
        return

    try:
        address = decode_address(debugger, args[0])
    except ValueError:
        return

    size = 0xFF

    if len(args) == 2:
        try:
            size = int(args[1], 0)
        except ValueError:
         return

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    error = lldb.SBError()
    data = process.ReadMemory(address, size, error)
    if error.Success():
        hexdump(data, address)
    else:
        print(error)


#############################################################################
# Stack trace                                                               #
#############################################################################


def isExecutable(debugger, address):

    target = debugger.GetSelectedTarget()

    for module in target.module_iter():
        for sec in module.section_iter():
            if sec.GetName() == "__TEXT":
                #print(hex(sec.GetFileAddress()), hex(address))
                if sec.GetFileAddress() < address < (sec.GetFileAddress()+sec.GetByteSize()):
                    return True

    return False


def show_displaydumppointers(debugger, command, result, internal_dict):
    command_args = shlex.split(command)
    #print(command_args)

    usage = "usage: ddp address [lines]"
    description='''Print a dump of the selected memory.'''
    parser = optparse.OptionParser(description=description, prog='xd', usage=usage)

    try:
        (options, args) = parser.parse_args(command_args)
    except:
        return

    if len(args) < 1:
        print(usage)
        return

    try:
        address = decode_address(debugger, args[0])
    except ValueError:
        return

    lines = 10
    if len(args) == 2:
        try:
            lines = int(args[1], 0)
        except ValueError:
         return


    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    error = lldb.SBError()


    for i in range(lines):
        data = process.ReadPointerFromMemory(address, error)
        if not error.Success():
            break

        output = ""
        output += Blue("0x{0:{1}}  ".format(address, arch_format))

        data2 = process.ReadPointerFromMemory(data, error)


        if error.Success() and isExecutable(debugger, data2):
            output += Red("0x{0:{1}}".format(data, arch_format))
        elif error.Success():
            output += Yellow("0x{0:{1}}".format(data, arch_format))
            output += "  -->  "
            output += "0x{0:{1}}  ".format(data2, arch_format)
        else:
            output += "0x{0:{1}}".format(data, arch_format)

        print(output)

        address += arch_size


#############################################################################
# List modules                                                              #
#############################################################################


def show_memorymap(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()

    for module in target.module_iter():
        for sec in module.section_iter():
            print(sec)


#############################################################################
# Stack trace                                                               #
#############################################################################


def show_stacktrace(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()

    for frame in thread:
        print str(frame)



#############################################################################
# IOS specific stuff                                                        #
#############################################################################


def show_directories(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetFrameAtIndex(0)

    # NSDocumentDirectory = 9 ; NSUserDomainMask = 1
    path = frame.EvaluateExpression('(NSString *)[NSSearchPathForDirectoriesInDomains(9, 1, YES) lastObject]').GetObjectDescription()
    print("Document path: {0}".format(path))

    path = frame.EvaluateExpression('(NSString *)NSTemporaryDirectory()').GetObjectDescription()
    print("Temporary path: {0}".format(path))


#############################################################################
# Main                                                                      #
#############################################################################


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('platform select remote-ios')
    debugger.HandleCommand('command script add -f ios.show_stacktrace kb')
    debugger.HandleCommand('command script add -f ios.show_registers r')
    debugger.HandleCommand('command script add -f ios.show_hexdump xd')
    debugger.HandleCommand('command script add -f ios.show_displaydumppointers ddp')
    debugger.HandleCommand('command script add -f ios.show_memorymap map')
    debugger.HandleCommand('command script add -f ios.show_directories directories')
