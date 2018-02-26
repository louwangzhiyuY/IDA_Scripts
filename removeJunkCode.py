# CodeRefsFrom  record all names and broad traverse
#import wingdbstub
# wingdbstub.Ensure()

patterns = {
    "je": "jne",
    "jne": "je",
    "js": "jns",
    "jns": "js",
    "jo": "jno",
    "jno": "jo",
    "jp": "jnp",
    "jnp": "jp",
    "jg": "jle",
    "jle": "jg",
    "jge": "jnl",
    "jnl": "jge",
    "jb": "jnb",
    "jnb": "jb",
    "jz": "jnz",
    "jnz": "jz",
    "jl": "jge",
    "jge": "jl",
    "jz": "jnz",
    "ja": "jbe",
    "jbe": "ja",
    "jc": "jnc",
    "jnc": "jc",
}


class MySet(object):
    def __init__(self):
        self.l = []

    def add(self, data):
        if data not in self.l:
            self.l.append(data)

    def __len__(self):
        return len(self.l)

    def get(self):
        if len(self.l) > 0:
            return self.l[0]
        else:
            return None

    def remove(self, data):
        if data in self.l:
            self.l.remove(data)

    def __iter__(self):
        return self.l.__iter__()


def removeJunkCode(start_addr):
    toAnalyseAddrs = MySet()
    AnalysedAddrs = MySet()
    addr = start_addr
    is_ret = False
    while addr != BADADDR:
        prev_addr = addr
        while not MakeCode(addr):
            prev_addr = PrevHead(prev_addr)
            MakeUnkn(prev_addr, 1)
        cur = "{}:{}".format(hex(addr), GetDisasm(addr))
        if addr in AnalysedAddrs:
            if len(toAnalyseAddrs) > 0:
                addr = toAnalyseAddrs.get()
                continue
            else:
                break
        elif addr in toAnalyseAddrs:
            toAnalyseAddrs.remove(addr)
            AnalysedAddrs.add(addr)

        if "ret" in GetMnem(addr):
            AnalysedAddrs.add(addr)

        elif GetMnem(addr) == "jmp":
            jmp_addr = GetOperandValue(addr, 0)
            MakeUnkn(addr + ItemSize(addr), 1)
            if jmp_addr not in AnalysedAddrs:
                toAnalyseAddrs.add(jmp_addr)
            print "after jmp:", hex(addr), GetDisasm(addr + ItemSize(addr))
            addr = jmp_addr

        elif GetMnem(addr) in patterns:
            if MakeCode(addr + ItemSize(addr)) and GetMnem(addr + ItemSize(addr)) == patterns[GetMnem(addr)]:
                jmp_addr = GetOperandValue(addr, 0)
                if GetOperandValue(addr, 0) == GetOperandValue(addr + ItemSize(addr), 0):
                    PatchByte(addr, 0xeb)  # jmp
                    AnalysedAddrs.remove(addr)
                    toAnalyseAddrs.add(addr)
                else:
                    PatchByte(addr + ItemSize(addr), 0xeb)  # jmp
                    if jmp_addr not in AnalysedAddrs:
                        toAnalyseAddrs.add(jmp_addr)
                    addr = addr + ItemSize(addr)

            else:
                jmp_addr = GetOperandValue(addr, 0)
                if jmp_addr not in AnalysedAddrs:
                    toAnalyseAddrs.add(jmp_addr)
                addr = addr + ItemSize(addr)
        else:
            addr = addr + ItemSize(addr)

    AnalyseArea(start_addr, MaxEA())
    print "remove junk code done"


removeJunkCode(here())
