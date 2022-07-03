import struct
import sys
from iced_x86 import Decoder, Formatter, FormatterSyntax

def GetSection(rva):
    sectionIndex = -1
    while sectionIndex+1 < len(sectionTable) and sectionTable[sectionIndex+1][0] <= rva:
        sectionIndex+=1
    section = sectionTable[sectionIndex]
    return section


def disassemble(ip, size):
    EXAMPLE_CODE_BITNESS = 64
    EXAMPLE_CODE = data[RVAtoRawPointer(ip, sectionTable):RVAtoRawPointer(ip, sectionTable)+size]
    decoder = Decoder(EXAMPLE_CODE_BITNESS, EXAMPLE_CODE, ip=ip)
    formatter = Formatter(FormatterSyntax.MASM)

    formatter.digit_separator = ""
    formatter.first_operand_char_index = 10

    for instr in decoder:
        disasm = formatter.format(instr)
        # You can also get only the mnemonic string, or only one or more of the operands:
        #   mnemonic_str = formatter.format_mnemonic(instr, FormatMnemonicOptions.NO_PREFIXES)
        #   op0_str = formatter.format_operand(instr, 0)
        #   operands_str = formatter.format_all_operands(instr)

        start_index = instr.ip - ip
        bytes_str = EXAMPLE_CODE[start_index:start_index + instr.len].hex().upper()
        # Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"        
        print(f"{instr.ip:016X} {bytes_str:20} {disasm}")

def instructionAt(ip):
    textBytes = data[RVAtoRawPointer(ip, sectionTable):RVAtoRawPointer(ip, sectionTable)+15]
    decoder = Decoder(64, textBytes, ip=ip)
    for instr in decoder:
        return (instr, textBytes[:instr.len])

def execute(ip):
    global textDecoded
    
    formatter = Formatter(FormatterSyntax.MASM)
    formatter.digit_separator = ""
    formatter.first_operand_char_index = 10
    
    executionEntries = [ip]

    while len(executionEntries):
        curIp = executionEntries[-1]
        executionEntries = executionEntries[:-1]
        #print("Resuming execution at", hex(curIp))
        while True:
            if textDecoded[curIp] != None:
                #print("Reached already decompiled part at", hex(curIp))
                break
            instr, textBytes = instructionAt(curIp)
            textDecoded[curIp] = instr
            curIp += instr.len
            disasm = formatter.format(instr)
            

            #print(f"Next: {instr.ip:016X} {textBytes.hex():20} {disasm:20}")
            #input()
            if disasm.startswith("ret"):
                
                #print("Returning")
                break
            if disasm.startswith("call"):
                try:
                    if disasm.endswith("]"):
                        destinationLocation = int(disasm[disasm.find("[")+1:disasm.find("]")-1], 16)
                        if disasm.split(" ")[-3] == "qword":
                            if GetSection(destinationLocation)[-1] == ".rdata":
                                
                                if destinationLocation in importedFunctions:
                                    print("Calling", importedFunctions[destinationLocation])
                                else:
                                    print("Calling address", destinationLocation, "located in rdata")                         
                    else:
                        destination = int(disasm.split(" ")[-1][:-1],16)
                        #print("Calling", hex(destination))
                        executionEntries.append(instr.ip+instr.len)
                        curIp = destination
                except:
                    print("Difficult call...")
                    print(f"Next: {instr.ip:016X} {textBytes.hex():20} {disasm:20}")

            if disasm.startswith("jmp"):
                try:
                    if disasm.endswith("]"):
                        destinationLocation = int(disasm[disasm.find("[")+1:disasm.find("]")-1], 16)
                        if disasm.split(" ")[-3] == "qword":
                            if GetSection(destinationLocation)[-1] == ".rdata":
                                if destinationLocation in importedFunctions:
                                    print("Jumping to", importedFunctions[destinationLocation])
                                else:
                                    print("Jumping to address", destinationLocation, "located in rdata")                         
                    else:
                        destination = int(disasm.split(" ")[-1][:-1],16)
                        #print("Jumping to", hex(destination))
                        curIp = destination
                except:
                    print("Difficult jmp")
                    print(f"Next: {instr.ip:016X} {textBytes.hex():20} {disasm:20}")

            elif disasm.startswith("j"):
                if disasm.endswith("]"):
                    pass
                else:
                    destination = int(disasm.split(" ")[-1][:-1],16)
                    #print("Conditional jump to", hex(destination), "registered")
                    executionEntries.append(destination)
                
            
            


def RVAtoRawPointer(rva, sectionTable):
    sectionIndex = -1
    while sectionIndex+1 < len(sectionTable) and sectionTable[sectionIndex+1][0] <= rva:
        sectionIndex+=1
    section = sectionTable[sectionIndex]
    if sectionIndex >= 0 and sectionIndex < len(sectionTable):
        if rva - section[0] <= section[1]:
            rawAddress = rva - section[0] + section[2]
            if rawAddress - section[2] <= section[3]:
                return rawAddress
    return None

with open(sys.argv[1], "rb") as f:
    data = f.read()

print("Length:", len(data))

readIndex = struct.unpack("=I",data[0x3C:0x3C+4])[0]
peHeader = data[readIndex:readIndex+24]
readIndex += 24

peHeader = struct.unpack("=IHHIIIHH", peHeader)
numberOfSections = peHeader[2]
optionalHeaderSize = peHeader[6]
pointerToSymbolTable = peHeader[4]

optionalHeader = data[readIndex:readIndex+optionalHeaderSize]

print(len(optionalHeader))

if optionalHeader[:2] == b"\x0b\x02":
    is64 = True
elif optionalHeader[:2] == b"\x0b\x01":
    is64 = False
else:
    raise RuntimeError("Neither x64 not x32")

if is64:
    mMagic,mMajorLinkerVersion,mMinorLinkerVersion,mSizeOfCode,mSizeOfInitializedData,mSizeOfUninitializedData,mAddressOfEntryPoint,mBaseOfCode,mImageBase,mSectionAlignment,mFileAlignment,mMajorOperatingSystemVersion,mMinorOperatingSystemVersion,mMajorImageVersion,mMinorImageVersion,mMajorSubsystemVersion,mMinorSubsystemVersion,mWin32VersionValue,mSizeOfImage,mSizeOfHeaders,mCheckSum,mSubsystem,mDllCharacteristics,mSizeOfStackReserve,mSizeOfStackCommit,mSizeOfHeapReserve,mSizeOfHeapCommit,mLoaderFlags,mNumberOfRvaAndSizes=struct.unpack("=HBB5IQ2I6H4I2H4Q2I", optionalHeader[:112])
else:
    mMagic,mMajorLinkerVersion,mMinorLinkerVersion,mSizeOfCode,mSizeOfInitializedData,mSizeOfUninitializedData,mAddressOfEntryPoint,mBaseOfCode,mBaseOfData,mImageBase,mSectionAlignment,mFileAlignment,mMajorOperatingSystemVersion,mMinorOperatingSystemVersion,mMajorImageVersion,mMinorImageVersion,mMajorSubsystemVersion,mMinorSubsystemVersion,mWin32VersionValue,mSizeOfImage,mSizeOfHeaders,mCheckSum,mSubsystem,mDllCharacteristics,mSizeOfStackReserve,mSizeOfStackCommit,mSizeOfHeapReserve,mSizeOfHeapCommit,mLoaderFlags,mNumberOfRvaAndSizes=struct.unpack("=HBB9I6H4I2H6I", optionalHeader[:96])

readIndex += optionalHeaderSize
print("Entry", mAddressOfEntryPoint)
print("Rva, size amount:", mNumberOfRvaAndSizes)

print("Image Base", mImageBase)

sectionTable = []
print(len(data))

memory = bytearray()
print(memory)

for section in range(numberOfSections):
    sectionData = data[readIndex:readIndex+40]
    readIndex += 40
    mName,mVirtualSize,mVirtualAddress,mSizeOfRawData,mPointerToRawData,mPointerToRelocations,mPointerToLinenumbers,mNumberOfRelocations,mNumberOfLinenumbers,mCharacteristics = struct.unpack("=8s6I2HI",sectionData)
    mName = mName[:mName.find(0)].decode("ascii")
    sectionTable.append((mVirtualAddress,mVirtualSize,mPointerToRawData, mSizeOfRawData, mName))
    print(mName,hex(mVirtualAddress),hex(mVirtualSize),hex(mPointerToRawData), hex(mSizeOfRawData))
    
print(sectionTable)

dataDirectories = {["exportTable", "importTable", "resourceTable", "exceptionTable", "attributeCertificateTableOffset", "baseRelocationTable", "debugData", "architecture", "GlobalPtr", "tls"][x] : x*8+96+is64*16 for x in range(10)}
for x in dataDirectories:
    address, size = struct.unpack("=II",optionalHeader[dataDirectories[x]:dataDirectories[x]+8])
    dataDirectories[x] = (RVAtoRawPointer(address, sectionTable),size)
    print(x, address, size)
    
    
importTableAddress, importTableSize = dataDirectories["importTable"]

importedFunctions = {}

readIndex = importTableAddress

if readIndex:
    while True:
        importData = struct.unpack("=5I",data[readIndex:readIndex+20])
        readIndex += 20
        
        if importData == (0,0,0,0,0):
            break
        OriginalFirstThunk,TimeDateStamp,ForwarderChain,Name,FirstThunk = importData
        NameStart = RVAtoRawPointer(Name, sectionTable)
        NameEnd = NameStart
        while data[NameEnd] != 0:
            NameEnd+=1
        Name = data[NameStart:NameEnd].decode("ascii")
        
        print(f"From {Name} import")


        OFTIBNreadIndex = RVAtoRawPointer(OriginalFirstThunk,sectionTable)
        AddressTable = FirstThunk
        while True:
            RVAToIIBN, = struct.unpack("=Q" if is64 else "=I",data[OFTIBNreadIndex:OFTIBNreadIndex+4 + is64*4])
            if RVAToIIBN == 0:
                break
            if RVAToIIBN & 0x80000000:
                RVAToIIBN ^= 0x80000000
                print("\t",Name, RVAToIIBN, "at", hex(AddressTable))
                importedFunctions[AddressTable] = f"{Name}_{RVAToIIBN}"
            elif RVAToIIBN & 0x8000000000000000:
                RVAToIIBN ^= 0x8000000000000000
                print("\t",Name, RVAToIIBN, "at", hex(AddressTable))
                importedFunctions[AddressTable] = f"{Name}_{RVAToIIBN}"
            else:
                RVAToIIBN = RVAtoRawPointer(RVAToIIBN, sectionTable)
                hint = struct.unpack("=H", data[RVAToIIBN:RVAToIIBN+2])
                RVAToIIBN+=2
                SubNameStart = RVAToIIBN
                while data[RVAToIIBN] != 0:
                    RVAToIIBN+=1
                print("\t", data[SubNameStart:RVAToIIBN].decode("ascii"), "at", hex(AddressTable))
                importedFunctions[AddressTable] = data[SubNameStart:RVAToIIBN].decode("ascii")
            OFTIBNreadIndex += 4 + is64*4
            AddressTable += 4 + is64*4

print(dataDirectories)

print(hex(mBaseOfCode))
print("Jump to execution start at", hex(RVAtoRawPointer(mAddressOfEntryPoint, sectionTable)))
print(hex(mAddressOfEntryPoint))
print(is64)


for section in sectionTable:
    if section[-1] == ".text":
        textDecoded = {x:None for x in range(section[0],section[0]+section[1])}

execute(mAddressOfEntryPoint)
