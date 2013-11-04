### A Python script for lldb to disassemble an Objective-C block

=================

A Python script for `lldb` that prints an Objective-C block signature and disassemble its invoke function.

In order to use the script in an embedded python interpreter using lldb you can import it by running the command

```
command script import /path/to/block_disass.py`
```

Alternatively, you can add `command script import /path/to/block_disass.py` to your `~/.lldbinit`.

Usage:

	block_disass variable

The following options are available:

	-d, --disass
			Disassembles the invoke function of the block. If no option is specified,
			--disass is assumed.
	
	-n, --number-instructions
			The number of instructions in the invoke function to disassemble.
	
	-s, --signature
			Prints the block signature, formatted with NSMethodSignature.
			
	Note that --number-instructions is only taken into account when used with --disass.
