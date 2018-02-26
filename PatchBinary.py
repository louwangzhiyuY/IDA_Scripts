import idc

def patchBinary(start, data, size = -1):
	if size < 0:
		size = len(data)
	else:
		size = min(len(data), size)
		
	for i in range(size):
		idc.PatchByte(start+i, ord(data[i]))
		
print """
Usage: 
    patchBinary(start_addr, patch_data, size<optional>)
"""
		