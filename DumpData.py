def dumpDataToFile(start_addr, size, filename):
	data = GetManyBytes(start_addr, size)
	fp = open(filename, 'wb')
	fp.write(data)
	fp.close()