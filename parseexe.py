import struct


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

with open("test.exe", "rb") as f:
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
    
    mMagic,mMajorLinkerVersion,mMinorLinkerVersion,mSizeOfCode,mSizeOfInitializedData,mSizeOfUninitializedData,mAddressOfEntryPoint,mBaseOfCode,mBaseOfData,mImageBase,mSectionAlignment,mFileAlignment,mMajorOperatingSystemVersion,mMinorOperatingSystemVersion,mMajorImageVersion,mMinorImageVersion,mMajorSubsystemVersion,mMinorSubsystemVersion,mWin32VersionValue,mSizeOfImage,mSizeOfHeaders,mCheckSum,mSubsystem,mDllCharacteristics,mSizeOfStackReserve,mSizeOfStackCommit,mSizeOfHeapReserve,mSizeOfHeapCommit,mLoaderFlags,mNumberOfRvaAndSizes=struct.unpack("=HBB9I6H4I2H6I", optionalHeader[:96])

    is64 = mMagic == 0x020b
    
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
        print(mName,mVirtualAddress,mVirtualSize,mSizeOfRawData,mPointerToRawData)
        
    
    dataDirectories = {["exportTable", "importTable", "resourceTable", "exceptionTable", "attributeCertificateTableOffset", "baseRelocationTable", "debugData", "architecture", "GlobalPtr", "tls"][x] : x*8+96+is64*16 for x in range(10)}
    for x in dataDirectories:
        address, size = struct.unpack("=II",optionalHeader[dataDirectories[x]:dataDirectories[x]+8])
        dataDirectories[x] = (RVAtoRawPointer(address, sectionTable),size)
        
        
    importTableAddress, importTableSize = dataDirectories["importTable"]
    
    readIndex = importTableAddress
    
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
        
        print("Importing library", Name)
        OFTIBNreadIndex = RVAtoRawPointer(OriginalFirstThunk,sectionTable)
        
        while True:
            RVAToIIBN, = struct.unpack("=I",data[OFTIBNreadIndex:OFTIBNreadIndex+4])
            OFTIBNreadIndex += 4
            
            if RVAToIIBN == 0:
                break
            RVAToIIBN = RVAtoRawPointer(RVAToIIBN, sectionTable)
            if RVAToIIBN:
                hint = struct.unpack("=H", data[RVAToIIBN:RVAToIIBN+2])
                RVAToIIBN+=2
                SubNameStart = RVAToIIBN
                while data[RVAToIIBN] != 0:
                    RVAToIIBN+=1
                print("\t", hint, data[SubNameStart:RVAToIIBN].decode("ascii"))
    
    print(dataDirectories)