#!/usr/bin/python

'''
Add this to ~/.lldbinit
command script import ~/.lldb/block.py
'''

import lldb
import commands
import optparse
import shlex

def __lldb_init_module (debugger, dict):
	debugger.HandleCommand('command script add -f block.block_disass_command block_disass')
	print 'The "block_disass" command has been installed'

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

def block_disass_command(debugger, command, result, dict):
	target = debugger.GetSelectedTarget()
	process = target.GetProcess()
	thread = process.GetSelectedThread()
	frame = thread.GetSelectedFrame()
	
	# If command is the variable name in the current frame
	address = frame.FindVariable(command).GetValueAsSigned()
	
	# If command is an address
	#address = int(command, 0)
	
	print_block_signature(debugger, process, address)
	disass_block_invoke_function(debugger, process, address, 35)
	
def print_block_signature(debugger, process, block_address):
	flags_address = block_address + 8	# The `flags` integer is 8 bytes in the struct
	
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
	
	block_descriptor_address = block_address + 24	# The block descriptor struct pointer is 24 bytes in the struct
	
	block_descriptor_error = lldb.SBError()
	block_descriptor = process.ReadPointerFromMemory(block_descriptor_address, block_descriptor_error)
	if not block_descriptor_error.Success():
		print "Could not read the block descriptor struct"
		return
	
	signature_address = block_descriptor + 16	# The signature is 16 bytes in the descriptor struct
	if block_has_copy_dispose_helpers:
		signature_address += 16	# If there are a copy and dispose function pointers the signature is 32 bytes in the descriptor struct
	
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

def disass_block_invoke_function(debugger, process, block_address, instruction_count):
	invoke_function_address = block_address + 16	# The `invoke` function is 16 bytes in the struct
	
	invoke_function_error = lldb.SBError()
	invoke_function_pointer = process.ReadPointerFromMemory(invoke_function_address, invoke_function_error)
	if not invoke_function_error.Success():
		print "Could not retrieve the block invoke function pointer"
		return
	
	disass_cmd = "disassemble --start-address " + str(invoke_function_pointer) + " -c " + str(instruction_count)
	debugger.HandleCommand(disass_cmd)
