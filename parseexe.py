import struct
import sys


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

for section in range(numberOfSections):
    sectionData = data[readIndex:readIndex+40]
    readIndex += 40
    mName,mVirtualSize,mVirtualAddress,mSizeOfRawData,mPointerToRawData,mPointerToRelocations,mPointerToLinenumbers,mNumberOfRelocations,mNumberOfLinenumbers,mCharacteristics = struct.unpack("=8s6I2HI",sectionData)
    mName = mName[:mName.find(0)].decode("ascii")
    sectionTable.append((mVirtualAddress,mVirtualSize,mPointerToRawData, mSizeOfRawData, mName))
    print(mName,hex(mVirtualAddress),hex(mVirtualSize),hex(mPointerToRawData), hex(mSizeOfRawData))
    

dataDirectories = {["exportTable", "importTable", "resourceTable", "exceptionTable", "attributeCertificateTableOffset", "baseRelocationTable", "debugData", "architecture", "GlobalPtr", "tls"][x] : x*8+96+is64*16 for x in range(10)}
for x in dataDirectories:
    address, size = struct.unpack("=II",optionalHeader[dataDirectories[x]:dataDirectories[x]+8])
    dataDirectories[x] = (RVAtoRawPointer(address, sectionTable),size)
    print(x, address, size)
    
    
importTableAddress, importTableSize = dataDirectories["importTable"]

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
        
        while True:
            RVAToIIBN, = struct.unpack("=Q" if is64 else "=I",data[OFTIBNreadIndex:OFTIBNreadIndex+4 + is64*4])
            OFTIBNreadIndex += 4 + is64*4
            if RVAToIIBN == 0:
                break
            if RVAToIIBN & 0x80000000:
                RVAToIIBN ^= 0x80000000
                print("\t",Name, RVAToIIBN)
            elif RVAToIIBN & 0x8000000000000000:
                RVAToIIBN ^= 0x8000000000000000
                print("\t",Name, RVAToIIBN)
            else:
                RVAToIIBN = RVAtoRawPointer(RVAToIIBN, sectionTable)
                hint = struct.unpack("=H", data[RVAToIIBN:RVAToIIBN+2])
                RVAToIIBN+=2
                SubNameStart = RVAToIIBN
                while data[RVAToIIBN] != 0:
                    RVAToIIBN+=1

                print("\t", data[SubNameStart:RVAToIIBN].decode("ascii"))

print(dataDirectories)

print(hex(mBaseOfCode))
print("Jump to execution start at", hex(RVAtoRawPointer(mAddressOfEntryPoint, sectionTable)))
print(is64)
toRun = data[RVAtoRawPointer(mAddressOfEntryPoint, sectionTable):RVAtoRawPointer(mAddressOfEntryPoint, sectionTable)+143360]


from iced_x86 import *
EXAMPLE_CODE_BITNESS = 64
EXAMPLE_CODE_RIP = mAddressOfEntryPoint
EXAMPLE_CODE = toRun

decoder = Decoder(EXAMPLE_CODE_BITNESS, EXAMPLE_CODE, ip=EXAMPLE_CODE_RIP)
formatter = Formatter(FormatterSyntax.NASM)

formatter.digit_separator = ""
formatter.first_operand_char_index = 10

for instr in decoder:
    disasm = formatter.format(instr)
    # You can also get only the mnemonic string, or only one or more of the operands:
    #   mnemonic_str = formatter.format_mnemonic(instr, FormatMnemonicOptions.NO_PREFIXES)
    #   op0_str = formatter.format_operand(instr, 0)
    #   operands_str = formatter.format_all_operands(instr)

    start_index = instr.ip - EXAMPLE_CODE_RIP
    bytes_str = EXAMPLE_CODE[start_index:start_index + instr.len].hex().upper()
    # Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
    
    if disasm.startswith("call"):
        print(f"{instr.ip:016X} {bytes_str:20} {disasm}")
        #callDest = int(disasm.split(" ")[-1][:-1],16)
        #callDest = RVAtoRawPointer(callDest, sectionTable)
        #print(callDest)
    
    else:
        continue
        
    
    if "[" in disasm:
        memoryAddress = disasm[disasm.find("["): disasm.find("]")-1]
        while memoryAddress and memoryAddress[0] not in "0123456789":
            memoryAddress = memoryAddress[1:]
        try:
            print(f"{instr.ip:016X} {bytes_str:20} {disasm}", hex(RVAtoRawPointer(int(memoryAddress,16), sectionTable)))
        except:
            pass
# Instruction also supports format specifiers, see the table below
decoder = Decoder(64, b"\x86\x64\x32\x16", ip=0x1234_5678)
instr = decoder.decode()

