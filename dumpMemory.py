import idaapi

def dumpMemoryToFile(start_addr, size, filename):
	data = idaapi.dbg_read_memory(start_addr, size)
	fp = open(filename, 'wb')
	fp.write(data)
	fp.close()