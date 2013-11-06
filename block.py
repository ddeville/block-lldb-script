#!/usr/bin/python

'''
Add this to ~/.lldbinit
command script import ~/.lldb/block.py
'''

import lldb
import commands
import shlex
import optparse

def __lldb_init_module (debugger, dict):
	debugger.HandleCommand('command script add -f block.block_disass_command block_disass')
	print 'The "block_disass" command has been installed'

def create_command_arguments(command):
	return shlex.split(command)

def create_block_disass_parser():
	usage = "usage: %prog arg1 [--disass -d] [--number-instructions -n] [--signature -s]"
	parser = optparse.OptionParser(prog='block_disass', usage=usage)
	parser.add_option('-d', '--disass', action='store_true', dest='disass', default=False)
	parser.add_option('-n', '--number-instructions', dest='numberinstructions', default=20)
	parser.add_option('-s', '--signature', action='store_true', dest='signature', default=False)
	return parser

def block_disass_command(debugger, command, result, dict):
	cmd_args = create_command_arguments(command)
	parser = create_block_disass_parser()
	
	try:
		(options, args) = parser.parse_args(cmd_args)
	except:
		return
	
	if len(args) == 0:
		print "You need to specify the name of a variable or an address"
		return
	
	variable_arg = args[0]
	number_instructions = options.numberinstructions
	should_signature = options.signature
	should_disass = options.disass or (not options.signature and not options.disass)
	
	target = debugger.GetSelectedTarget()
	process = target.GetProcess()
	thread = process.GetSelectedThread()
	frame = thread.GetSelectedFrame()
		
	variable = frame.FindVariable(variable_arg)
	if variable.IsValid():
		address = variable.GetValueAsSigned()
	else:
		try:
			address = int(variable_arg, 0)
		except:
			print "The argument is not a valid address or variable in the frame"
			return
	
	if should_signature:
		print_block_signature(debugger, target, process, address)
	if should_disass:
		disass_block_invoke_function(debugger, target, process, address, number_instructions)

'''
struct Block_literal_1 {
    void *isa;
    int flags;
    int reserved; 
    void (*invoke)(void *, ...);
    struct Block_descriptor_1 {
        unsigned long int reserved;
        unsigned long int size;
        void (*copy_helper)(void *dst, void *src);
        void (*dispose_helper)(void *src);
        const char *signature;
    } *descriptor;
};
'''

def print_block_signature(debugger, target, process, block_address):
	pointer_size = 8 if arch_for_target_is_64bit(target) else 4
	
	flags_address = block_address + pointer_size	# The `flags` integer is after a pointer in the struct
	
	flags_error = lldb.SBError()
	flags = process.ReadUnsignedFromMemory(flags_address, 4, flags_error)
	if not flags_error.Success():
		print "Could not retrieve the block flags"
		return
	
	block_has_signature = ((flags & (1 << 30)) != 0)	# BLOCK_HAS_SIGNATURE = (1 << 30)
	block_has_copy_dispose_helpers = ((flags & (1 << 25)) != 0) # BLOCK_HAS_COPY_DISPOSE = (1 << 25)
	
	if not block_has_signature:
		print "The block does not have a signature"
		return
	
	block_descriptor_address = block_address + 2 * 4 + 2 * pointer_size	# The block descriptor struct pointer is after 2 pointers and 2 int in the struct
	
	block_descriptor_error = lldb.SBError()
	block_descriptor = process.ReadPointerFromMemory(block_descriptor_address, block_descriptor_error)
	if not block_descriptor_error.Success():
		print "Could not read the block descriptor struct"
		return
	
	signature_address = block_descriptor + 2 * pointer_size	# The signature is after 2 unsigned int in the descriptor struct
	if block_has_copy_dispose_helpers:
		signature_address += 2 * pointer_size	# If there are a copy and dispose function pointers the signature
	
	signature_pointer_error = lldb.SBError()
	signature_pointer = process.ReadPointerFromMemory(signature_address, signature_pointer_error)
	
	signature_error = lldb.SBError()
	signature = process.ReadCStringFromMemory(signature_pointer, 256, signature_error)
	if not signature_error.Success():
		print "Could not retrieve the signature"
		return
	
	escaped_signature = signature.replace('"', '\\"')
	
	method_signature_cmd = 'po [NSMethodSignature signatureWithObjCTypes:"' + escaped_signature + '"]'
	debugger.HandleCommand(method_signature_cmd)

def disass_block_invoke_function(debugger, target, process, block_address, instruction_count):
	pointer_size = 8 if arch_for_target_is_64bit(target) else 4
	
	invoke_function_address = block_address + pointer_size + 2 * 4	# The `invoke` function is after one pointer and 2 int in the struct
	
	invoke_function_error = lldb.SBError()
	invoke_function_pointer = process.ReadPointerFromMemory(invoke_function_address, invoke_function_error)
	if not invoke_function_error.Success():
		print "Could not retrieve the block invoke function pointer"
		return
	
	disass_cmd = "disassemble --start-address " + str(invoke_function_pointer) + " -c " + str(instruction_count)
	debugger.HandleCommand(disass_cmd)

arch_64 = ['armv64', 'x86_64']
arch_32 = ['i386', 'armv7', 'armv7s']

def arch_for_target_is_64bit(target):
	arch = target.GetTriple().split('-')[0]
	return arch in arch_64
