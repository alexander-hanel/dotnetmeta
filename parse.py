import struct

"""
Reads
c    http://ntcore.com/files/dotnetformat.htm
    https://codingwithspike.wordpress.com/2012/09/01/building-a-net-disassembler-part-4-reading-the-metadata-tables-in-the-stream/
    http://www.visualcplusdotnet.com/visualcplusdotnet5a.html
    https://www.simple-talk.com/blogs/2011/03/21/anatomy-of-a-net-assembly-clr-metadata-3/
    https://github.com/crackinglandia/pype32/blob/master/pype32/dotnet.py
Books
    Expert .NET 2.0 IL Assembler
"""

metadata_tables = ["Module", "TypeRef", "TypeDef", "FieldPtr", "Field", "MethodPtr", "MethodDef",
           "ParamPtr", "Param", "InterfaceImpl", "MemberRef", "Constant", "CustomAttribute",
           "FieldMarshal", "DeclSecurity", "ClassLayout", "FieldLayout", "StandAloneSig",
           "EventMap", "EventPtr", "Event", "PropertyMap", "PropertyPtr", "Property",
           "MethodSemantics", "MethodImpl", "ModuleRef", "TypeSpec", "ImplMap", "FieldRVA",
           "ENCLog", "ENCMap", "Assembly", "AssemblyProcessor", "AssemblyOS", "AssemblyRef",
           "AssemblyRefProcessor", "AssemblyRefOS", "File", "ExportedType", "ManifestResource",
           "NestedClass", "GenericParam", "MethodSpec", "GenericParamConstraint"]


class IMAGE_DATA_DIRECTORY:
    def __init__(self):
        self.VirtualAddress = None  # DWORD
        self.Size = None  # DWORD


class IMAGE_FILE_HEADER:
    def __init__(self):
        self.Machine = None  # WORD
        self.NumberOfSections = None  # WORD
        self.TimeDateStamp = None  # DWORD
        self.PointerToSymbolTable = None  # DWORD
        self.NumberOfSymbols = None  # DWORD
        self.SizeOfOptionalHeader = None  # WORD
        self.Characteristics = None  # WORD
        self._offset = None


class IMAGE_SECTION_HEADER:
    def __init__(self):
        self.Name = None  # BYTE
        self.VirtualSize = None  # DWORD
        self.VirtualAddress = None  # DWORD
        self.SizeOfRawData = None  # DWORD
        self.PointerToRawData = None  # DWORD
        self.PointerToRelocations = None  # DWORD
        self.PointerToLinenumbers = None  # DWORD
        self.NumberOfRelocations = None  # WORD
        self.NumberOfLinenumbers = None  # WORD
        self.Characteristics = None  # DWORD


class IMAGE_OPTIONAL_HEADER:
    def __init__(self):
        self.end = None
        self.Magic = None # WORD
        self.MajorLinkerVersion = None  # BYTE
        self.MinorLinkerVersion = None  # BYTE
        self.SizeOfCode = None  # DWORD
        self.SizeOfInitializedData = None  # DWORD
        self.SizeOfUninitializedData = None  # DWORD
        self.AddressOfEntryPoint = None  # DWORD
        self.BaseOfCode = None  # DWORD
        self.BaseOfData = None  # DWORD
        self.ImageBase = None  # DWORD
        self.SectionAlignment = None  # DWORD
        self.FileAlignment = None  # DWORD
        self.MajorOperatingSystemVersion = None  # WORD
        self.MinorOperatingSystemVersion = None  # WORD
        self.MajorImageVersion = None  # WORD
        self.MinorImageVersion = None  # WORD
        self.MajorSubsystemVersion = None  # WORD
        self.MinorSubsystemVersion = None  # WORD
        self.Win32VersionValue = None  # DWORD
        self.SizeOfImage = None  # DWORD
        self.SizeOfHeaders = None  # DWORD
        self.CheckSum = None  # DWORD
        self.Subsystem = None  # WORD
        self.DllCharacteristics = None  # WORD
        self.SizeOfStackReserve = None  # DWORD
        self.SizeOfStackCommit = None  # DWORD
        self.SizeOfHeapReserve = None  # DWORD
        self.SizeOfHeapCommit = None  # DWORD
        self.LoaderFlags = None  # DWORD
        self.NumberOfRvaAndSizes = None  # DWORD
        self.DataDirectory = []  # IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]


class StreamHeaders:
    def __init__(self):
        self.offset = None
        self.size = None
        self.name = ""


class MetaDataHeader:
    def __init__(self):
        self.Signature = "\x42\x53\x4a\x42"
        self.MajorVersion = None
        self.MinorVersion = None
        self.Reserved = None
        self.Length = None
        self.Version = None
        self.Flags = None
        self.Streams = None
        self.StreamHeaders = []
        self.offset = 0


class IMAGE_COR20_HEADER:
    def __init__(self):
        # Header version
        self.cb = None  # DWORD, offset 0
        self.MajorRunTimeVersion = None  # WORD, offset 4
        self.MinorRunTimeVersion = None  # WORD, offset 6
        # Symbol table and startup information
        self.MetaData = None  # QWORD, offset 8
        self.Flags = None  # WORD, offset 16
        self.EntryPointToken = None  # WORD, offset 20
        self.Resources = IMAGE_DATA_DIRECTORY()  # offset 24
        self.StrongNameSignature = IMAGE_DATA_DIRECTORY()  # QWORD, offset 32
        self.CodeManagerTable = IMAGE_DATA_DIRECTORY()  # QWORD, offset 40
        self.VTableFixups = IMAGE_DATA_DIRECTORY()   # QWORD, offse 48
        self.ExportAddressTableJumps = IMAGE_DATA_DIRECTORY()  # QWORD, offset 56
        self.ManageNativeHeaders = IMAGE_DATA_DIRECTORY()  # QWORD, offset 64


class METADATA_TABLE_STREAM_HEADER:
    def __init__(self):
        self.Reserved = None  # DWORD
        self.Major = None  # BYTE
        self.Minor = None  # BYTE
        self.Heaps = None  # BYTE
        self.Rid = None  # BYTE
        self.MaskValid = None  # QWORD
        self.Sorted = None  # QWORD
        self.Rows = [] # list of n 4-byte unsigned integers indicating the number of rows for each present table
        self.Tables = None
        self._table_values = None
        self._end = None


class METADATA_TABLE_DESCRIPTOR:
    def __init__(self):
        self.pColDefs = None  # POINTER
        self.cCols = None  # BYTE
        self.iKey = None  # BYTE
        self.cbRec = None  # WORD


class METADATA_TABLE_COLUMN_DESCRIPTOR:
    def __init__(self):
        self.Type = None  # BYTE
        self.oColumn = None  # BYTE
        self.cbColumn = None  # BYTE


class METADATA_SCHEME():
    def __init__(self):
        self.scheme = []
        self.metadata_table_names = {
            0x00: "Module",
            0x01: "TypeRef",
            0x02: "TypeDef",
            0x03: "FieldPtr",
            0x04: "Field",
            0x05: "MethodPtr",
            0x06: "MethodDef",
            0x07: "ParamPtr",
            0x08: "Param",
            0x09: "InterfaceImpl",
            0x0a: "MemberRef",
            0x0b: "Constant",
            0x0c: "CustomAttribute",
            0x0d: "FieldMarshal",
            0x0e: "DeclSecurity",
            0x0f: "ClassLayout",
            0x10: "FieldLayout",
            0x11: "StandAloneSig",
            0x12: "EventMap",
            0x13: "EventPtr",
            0x14: "Event",
            0x15: "PropertyMap",
            0x16: "PropertyPtr",
            0x17: "Property",
            0x18: "MethodSemantics",
            0x19: "MethodImpl",
            0x1a: "ModuleRef",
            0x1b: "TypeSpec",
            0x1c: "ImplMap", # TODO specs are different
            0x1d: "FieldRVA",
            0x1e: "ENCLog",
            0x1f: "ENCMap",
            0x20: "Assembly",
            0x21: "AssemblyProcessor",  # unused
            0x22: "AssemblyOS",  # unused
            0x23: "AssemblyRef",
            0x24: "AssemblyRefProcessor",  # unused
            0x25: "AssemblyRefOS",  # unused
            0x26: "File",
            0x27: "ExportedType",
            0x28: "ManifestResource",
            0x29: "NestedClass",
            0x2a: "GenericParam",
            0x2b: "MethodSpec",
            0x2c: "GenericParamConstraint",
            }
        self.present_in_optimized = {
            0x0: True,  # Module
            0x1: True,  # TypeRef
            0x2: True,  # TypeDef
            0x3: False,  # FieldPtr
            0x4: True,  # Field
            0x5: False,  # MethodPtr
            0x6: True,  # Method
            0x7: False,  # ParamPtr
            0x8: True,  # Param
            0x9: True,  # InterfaceImpl
            0xa: True,  # MemberRef
            0xb: True,  # Constant
            0xc: True,  # CustomAttribute
            0xd: True,  # FieldMarshal
            0xe: True,  # DeclSecurity
            0xf: True,  # ClassLayout
            0x10: True,  # FieldLayout
            0x11: True,  # StandAloneSig
            0x12: True,  # EventMap
            0x13: False,  # EventPtr
            0x14: True,  # Event
            0x15: True,  # PropertyMap
            0x16: False, # PropertyPtr
            0x17: True,  # Property
            0x18: True,  # MethodSemantics
            0x19: True,  # MethodImpl
            0x1a: True,  # ModuleRef
            0x1b: True,  # ModuleRef
            0x1c: True,  # ImplMap
            0x1d: True,  # FieldRVA
            0x1e: False,  # ENCLog  # reserved for future use
            0x1f: False,  # ENCMap  # reserved for future use
            0x20: True,  # Assembly
            0x21: True,  # AssemblyProcessor
            0x22: True,  # AssemblyOS
            0x23: True,  # AssemblyRef
            0x24: True,  # AssemblyRefProcessor
            0x25: True,  # AssemblyRefOS
            0x26: True,  # File
            0x27: True,  # ExportedType
            0x28: True,  # ManifestResource
            0x29: True,  # NestedClass
            0x2a: True,  # GenericParam
            0x2b: True,  # MethodSpec
            0x2c: True,  # GenericParamConstraint
            }

    def check_if_present(self, value):
        if self.present_in_optimized[value] is True:
            return True
        else:
            return False


class COLUMNS:
    def __init__(self):
        self.tables = {
            "Module": [("Generation", "USHORT"), ("Name", "STRING"),("Mvid", "GUID"), ("EncId", "GUID"),
                       ("EncBaseId", "GUID")],
            # TODO resolutionscope
            "TypeRef": [("ResolutionScope", "RESOLUTIONSCOPE" ), ("Name", "STRING"), ("NameSpace", "STRING") ],
            "TypeDef": [("Flags", "ULONG"), ("Name", "STRING"), ("Namespace", "STRING"), ("Extends", "TypeDefOrRef"),
                         ("FieldList", "RID"), ("MethodList", "RID")] ,
            "FieldPtr": [("Field", "RID")],
            "Field": [("Flags", "USHORT"), ("Name", "STRING"), ("Signature", "BLOB")],
            "MethodPtr": [("Method", "RID")],
            "MethodDef": [("RVA", "ULONG"), ("ImplFlags", "USHORT"), ("Flags", "USHORT"), ("Name", "STRING"),
                          ("Signature", "BLOB"),
                           ("ParamList", "RID")],
            "ParamPtr": [("Param", "RID")],
            "Param": [("Flags", "USHORT"), ("Sequence", "USHORT"), ("Name", "STRING")],
            "InterfaceImpl": [("Class", "RID" ), ("Interface", "TypeDefOrRef")],
            "MemberRef": [("Class", "MemberRefParent"), ("Name", "STRING"), ("Signature", "BLOB")],
            "Constant": [("Type", "BYTE"), ("Parent", "HasConstant"), ("Value", "BLOB")],
            "CustomAttribute": [("Parent", "HasCustomAttribute"), ("Type", "CustomAttributeType"), ("Value", "BLOB")],
            "FieldMarshal": [("Parent", "FieldMarshal"), ("NativeType", "BLOB")],
            "DeclSecurity": [("Action", "SHORT"), ("Parent", "HasDeclSecurity"), ("PermissionSet", "BLOB")],
            "ClassLayout": [("PackingSize", "WORD"), ("ClassSize", "DWORD"), ("Parent", "TypeDef")],
            "FieldLayout": [("Offset", "ULONG"), ("Field", "RID")],
            "StandAloneSig": [("Signature", "BLOB")],
            "EventMap": [("Parent", "RID"), ("EventList", "RID")],
            "EventPtr": [("Event", "RID")],
            "Event": [("EventFlags", "USHORT"), ("Name", "STRING"), ("EventType", "TypeDefOrRef")],
            "PropertyMap": [("Parent", "RID"), ("PropertyList", "RID")],
            "PropertyPtr": [("Property", "RID")],
            "Property": [("PropFlags", "USHORT"), ("Name", "STRING"), ("Type", "BLOB")],
            "MethodSemantics": [("Semantic", "USHORT"), ("Method", "RID"), ("Association","HasSemantic" )],
            "MethodImpl": [("Class", "RID"), ("MethodBody", "MethodDefOrRef"), ("MethodDeclaration", "MethodDefOrRef")],
            "ModuleRef": [("Name", "STRING")],
            "TypeSpec": [("Signature", "BLOB")],
            "ImplMap": [("MappingFlags", "USHORT" ), ("MemberForwarded", "MemberForwarded"), ("ImportName", "STRING" ),
                        ("ImportScope", "RID" )],
            "FieldRVA": [("RVA", "ULONG" ), ("Field", "RID")],
            "ENCLog": [("Token", "ULONG" ), ("FuncCode", "ULONG")],
            "ENCMap": [("Token", "ULONG" )],
            "Assembly": [("HashAlgId", "ULONG"), ("MajorVersion", "USHORT"), ("MinorVersion", "USHORT"),
                                      ("RevisionNumber", "USHORT"), ("Flags", "ULONG"), ("PublicKey", "BLOB"),
                         ("Name", "STRING"),
                                      ("Culture", "STRING")],
            "AssemblyProcessor": [("Processor", "ULONG")],
            "AssemblyOS": [("OSPlatformID", "ULONG"), ("OSMajorVersion", "ULONG"), ("OSMinorVersion", "ULONG6")],
            "AssemblyRef"  : [("MajorVersion", "WORD"), ("MinorVersion", "WORD"), ("BuildNumber","WORD"),
                                         ("RevisionNumber", "WORD"), ("Flags", "DWORD"), ("PublicKeyOrToken", "BLOB"),
                              ("Name", "STRING"),
                                         ("Name", "STRING"), ("Culture", "STRING"), ("HashValue", "BLOB")],
            "AssemblyRefProcessor": [("Processor", "DWORD"), ("RID", "AssemblyRef")],
            "AssemblyRefOS": [("OSPlatformId", "DWORD"),("OSMajorVersion", "DWORD"), ("OSMinorVersion", "DWORD"),
                                           ("AssemblyRef", "AssemblyRef")],
            "File": [("Flags", "ULONG" ), ("Name", "STRING"), ("HashValue", "BLOB")],
            "ExportedType":[ ("Flags", "ULONG" ), ("TypeDefId", "ULONG"), ("TypeName", "STRING"),
                             ("TypeNamespace", "STRING"),
                              ("Implementation", "Implementation")],
            "ManifestResource": [("Offset", "ULONG" ), ("Flags", "ULONG"), ("Name", "STRING" ),
                                 ("Implementation", "Implementation")],
            "NestedClass": [("NestedClass", "RID" ), ("EnclosingClass", "RID")],
            "GenericParam": [("Number", "USHORT" ), ("Flags", "USHORT"), ("Owner", "TypeOrMethodDef"),
                             ("Name", "STRING")],
            "MethodSpec": [("Method", "MethodDefOrRef" ), ("Instantiation", "Blob")],
            "GenericParamConstraint": [("Owner", "Rid" ), ("Constraint", "TypeDefOrRef")]
        }


def round_bytes(value):
    rounder = 4
    remainder = value % rounder
    if remainder == 0:
        return value
    return value + rounder - remainder


def read_till_zero(offset, data):
    byte = data[offset: offset + 1]
    while byte is not "\x00" and offset < len(data):
        offset += 1
        byte = data[offset: offset + 1]
    if offset >= len(data):
        return None
    return offset

def get_data(length, offset, data):
    """
    Read different byte sizes
    """
    temp_data = ""
    temp_buff = 0
    if length is 1:
        temp_data = data[offset: offset + 1]
        temp_buff = struct.unpack("<B", temp_data)[0]
    elif length is 2:
        temp_data = data[offset: offset + 2]
        temp_buff = struct.unpack("<H", temp_data)[0]
        pass
    elif length is 4:
        temp_data = data[offset: offset + 4]
        temp_buff = struct.unpack("<I", temp_data)[0]
    elif length is 8:
        temp_data = data[offset: offset + 8]
        temp_buff = struct.unpack("<Q", temp_data)[0]
    return temp_buff

def get_image_file_header(pe_data):
    if pe_data[:2] != "MZ":
        print "ERROR: Invalid DOS Header"
        return None
    e_lfanew = struct.unpack("<i", pe_data[0x3c:0x40])[0]
    if "PE" not in str(pe_data[e_lfanew: e_lfanew + 2]):
        print "ERROR: PE Signature was not found!"
        return None
    ifh = IMAGE_FILE_HEADER()
    ifh._offset = e_lfanew + 4
    cur_addr = ifh._offset
    ifh.Machine = get_data(2, cur_addr, pe_data)
    cur_addr += 2
    ifh.NumberOfSections = get_data(2, cur_addr, pe_data)
    cur_addr += 2
    ifh.TimeDateStamp = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ifh.PointerToSymbolTable = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ifh.NumberOfSymbols = get_data(4,    cur_addr, pe_data)
    cur_addr += 4
    ifh.SizeOfOptionalHeader = get_data(2, cur_addr, pe_data)
    cur_addr += 2
    ifh.Characteristics = get_data(2, cur_addr, pe_data)
    return ifh


def get_image_data_directory(pe_data, cur_addr):
    idd = IMAGE_DATA_DIRECTORY()
    idd.VirtualAddress = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    idd.Size = get_data(4, cur_addr, pe_data)
    return idd


def get_image_optional_header(data, start):
    IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
    if start is None:
        #TODO
        print "ERRRRRR..."
        return None
    cur_addr = start + 20
    ioh = IMAGE_OPTIONAL_HEADER()
    temp_data = data[cur_addr: cur_addr + 2]
    ioh.Magic = struct.unpack("<H", temp_data)[0]
    cur_addr += 2
    temp_data = data[cur_addr: cur_addr + 1]
    ioh.MajorLinkerVersion = struct.unpack("<B", temp_data)[0]
    cur_addr += 1
    temp_data = data[cur_addr: cur_addr + 1]
    ioh.MinorLinkerVersion = struct.unpack("<B", temp_data)[0]
    cur_addr += 1
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.SizeOfCode = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.SizeOfInitializedData = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.SizeOfUninitializedData = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.AddressOfEntryPoint = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.BaseOfCode = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.BaseOfData = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.ImageBase = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.SectionAlignment = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.FileAlignment = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 2]
    ioh.MajorOperatingSystemVersion = struct.unpack("<H", temp_data)[0]
    cur_addr += 2
    temp_data = data[cur_addr: cur_addr + 2]
    ioh.MinorOperatingSystemVersion = struct.unpack("<H", temp_data)[0]
    cur_addr += 2
    temp_data = data[cur_addr: cur_addr + 2]
    ioh.MajorImageVersion = struct.unpack("<H", temp_data)[0]
    cur_addr += 2
    temp_data = data[cur_addr: cur_addr + 2]
    ioh.MinorImageVersion = struct.unpack("<H", temp_data)[0]
    cur_addr += 2
    temp_data = data[cur_addr: cur_addr + 2]
    ioh.MajorSubsystemVersion = struct.unpack("<H", temp_data)[0]
    cur_addr += 2
    temp_data = data[cur_addr: cur_addr + 2]
    ioh.MinorSubsystemVersion = struct.unpack("<H", temp_data)[0]
    cur_addr += 2
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.Win32VersionValue = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.SizeOfImage = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.SizeOfHeaders = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.CheckSum = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 2]
    ioh.Subsystem = struct.unpack("<H", temp_data)[0]
    cur_addr += 2
    temp_data = data[cur_addr: cur_addr + 2]
    ioh.DllCharacteristics = struct.unpack("<H", temp_data)[0]
    cur_addr += 2
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.SizeOfStackReserve = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.SizeOfStackCommit = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.SizeOfHeapReserve = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.SizeOfHeapCommit = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.LoaderFlags = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    temp_data = data[cur_addr: cur_addr + 4]
    ioh.NumberOfRvaAndSizes = struct.unpack("<I", temp_data)[0]
    cur_addr += 4
    for entries in range(0, IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
        ioh.DataDirectory.append(get_image_data_directory(data, cur_addr))
        cur_addr += 8
    ioh.end = cur_addr
    return ioh


def read_image_section_header(pe_data, cur_addr):
    ish = IMAGE_SECTION_HEADER()
    ish.Name = pe_data[cur_addr: cur_addr + 8]
    cur_addr += 8
    ish.VirtualSize = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ish.VirtualAddress = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ish.SizeOfRawData = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ish.PointerToRawData = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ish.PointerToRelocations = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ish.PointerToLinenumbers = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ish.NumberOfRelocations = get_data(2, cur_addr, pe_data)
    cur_addr += 2
    ish.NumberOfLinenumbers = get_data(2, cur_addr, pe_data)
    cur_addr += 2
    ish.Characteristics = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    return ish


def read_common_language_runtime_header(pe_data, cur_addr):
    ich = IMAGE_COR20_HEADER()
    ich.cb = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.MajorRunTimeVersion = get_data(2, cur_addr, pe_data)
    cur_addr += 2
    ich.MinorRunTimeVersion = get_data(2, cur_addr, pe_data)
    cur_addr += 2
    ich.MetaData = IMAGE_DATA_DIRECTORY()
    ich.MetaData.VirtualAddress = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.MetaData.Size = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    # TODO: 32 and 64 bit ??
    ich.Flags = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.EntryPointToken = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.Resources = IMAGE_DATA_DIRECTORY()
    ich.Resources.VirtualAddress = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.Resources.Size = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.StrongNameSignature = IMAGE_DATA_DIRECTORY()
    ich.StrongNameSignature.VirtualAddress = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.StrongNameSignature.Size = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.CodeManagerTable = IMAGE_DATA_DIRECTORY()
    ich.CodeManagerTable.VirtualAddress = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.CodeManagerTable.Size = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.VTableFixups = IMAGE_DATA_DIRECTORY()
    ich.VTableFixups.VirtualAddress = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.VTableFixups.Size = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.ExportAddressTableJumps = IMAGE_DATA_DIRECTORY()
    ich.ExportAddressTableJumps.VirtualAddress = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.ExportAddressTableJumps.Size = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.ManageNativeHeaders = IMAGE_DATA_DIRECTORY()
    ich.ManageNativeHeaders.VirtualAddress = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    ich.ManageNativeHeaders.Size = get_data(4, cur_addr, pe_data)
    return ich


def read_metadata_header(cur_addr ,data):
    # TODO: replace the struct code
    metadata_header = MetaDataHeader()
    # Signature is a dword of 0x424A5342
    temp_addr = find_signature(data, metadata_header.Signature)
    if temp_addr != cur_addr:
        print "ERROR: Header Address incorrectly parsed"
        return None
    metadata_header.offset = cur_addr
    if metadata_header.offset is None:
        return -1
    # skip over Signature. cur_addr is at MajorVersion offset
    cur_addr = metadata_header.offset + 4
    temp = data[cur_addr: cur_addr + 2]
    metadata_header.MajorVersion = struct.unpack("<H", temp)[0]
    # skip over MajorVersion. cur_addr is at MinorVersion offset
    cur_addr += 2
    metadata_header.MinorVersion = struct.unpack("<H", temp)[0]
    # skip over MinorVersion. cur_addr is at Reserved offset
    cur_addr += 2
    # Reserved: A DWORD, the value of which is always 0.
    temp = data[cur_addr: cur_addr + 4]
    metadata_header.Reserved = struct.unpack("<i", temp)[0]
    # skip over Reserved, cur_addr is a Length
    cur_addr += 4
    # Length: The length of the UTF string that follows (it's the version string,
    # something like: "v1.1.4322"). The length has to be rounded up to a multiple of 4.
    temp_offset = read_till_zero(cur_addr, data)
    if temp_offset is None:
        return None
    temp_len = temp_offset - cur_addr
    metadata_header.Length = get_data(temp_len, cur_addr, data)
    # skip over length, cur_addr is the version string
    cur_addr = round_bytes(cur_addr + temp_len)
    metadata_header.Version = data[cur_addr: cur_addr + metadata_header.Length]
    # skip over version string and round to the next four byte
    # cur_addr is at the flags
    cur_addr = round_bytes(cur_addr + metadata_header.Length)
    temp = data[cur_addr: cur_addr + 2]
    metadata_header.Flags = struct.unpack("<H", temp)[0]
    # skip over flags, cur_addr is streams
    cur_addr += 2
    # Streams: A word telling us the number of streams present in the MetaData.
    temp = data[cur_addr: cur_addr + 2]
    metadata_header.Streams = struct.unpack("<H", temp)[0]
    # skip over stream, cur_addr is at StreamHeaders
    cur_addr += 2
    # A stream header is made of two DWORDs (an offset and
    # a size) and an ASCII string aligned to the next 4-byte boundary.
    # loop through each stream
    for stream in range(0, metadata_header.Streams):
        st = StreamHeaders()
        temp = data[cur_addr: cur_addr + 4]
        st.offset = struct.unpack("<i", temp)[0]
        # skip over offset, cur_addr is at size
        cur_addr += 4
        temp = data[cur_addr: cur_addr + 4]
        st.size = struct.unpack("<i", temp)[0]
        # skip over size, cur_addr is at name
        cur_addr += 4
        temp_offset = read_till_zero(cur_addr, data) + 1
        if temp_offset is None:
            return None
        temp_len = temp_offset - cur_addr
        st.name = data[cur_addr: cur_addr + temp_len]
        cur_addr = round_bytes(cur_addr + temp_len)
        metadata_header.StreamHeaders.append(st)
    return metadata_header


def get_metadata_scheme(offset, optimized=True ):
    columns = COLUMNS()
    for x in columns.tables:
        print columns.tables[x]

def read_metadata_table_stream_header(cur_addr, pe_data):
    mtsh = METADATA_TABLE_STREAM_HEADER()
    mtsh.Reserved = get_data(4, cur_addr, pe_data)
    cur_addr += 4
    mtsh.Major = get_data(1, cur_addr, pe_data)
    cur_addr += 1
    mtsh.Minor = get_data(1, cur_addr, pe_data)
    cur_addr += 1
    mtsh.Heaps = get_data(1, cur_addr, pe_data)
    cur_addr += 1
    mtsh.Rid = get_data(1, cur_addr, pe_data)
    cur_addr += 1
    mtsh.MaskValid = get_data(8, cur_addr, pe_data)
    cur_addr += 8
    mtsh.Sorted = get_data(8, cur_addr, pe_data)
    cur_addr += 8
    """NOTE: pg 79 IL -- sequence of 4-byte unsigned integers indicating the number
              of records in each table marked 1 in the MaskValid bit vector"""
    # quick bit vector hack using strings
    # value to string binary, reverse, remove 0b then count location of 1
    bits = bin(mtsh.MaskValid)[::-1][:-2]
    mtsh._table_values = [i for i, ltr in enumerate(bits) if ltr == "1"]
    # Each table has a unique schema. Overview: get table value, check if table is present in format
    # some tables are not present in optimized metadata. If not present, get next table name
    for row in range(0, len(mtsh._table_values)):
        mtsh.Rows.append(get_data(4, cur_addr, pe_data))
        cur_addr += 4
    mtsh._end = cur_addr
    return mtsh


def create_metadata_table(mtsh, optimized):
    # mtsh instance of METADATA_TABLE_STREAM_HEADER
    ms = METADATA_SCHEME()
    bits = bin(mtsh.MaskValid)[::-1][:-2]
    table_values = [i for i, ltr in enumerate(bits) if ltr == "1"]
    for index, table in enumerate(mtsh._table_values):
        # Some tables do not exist in optimized metadata, if the table value is present go to the next table
        if optimized:
            if ms.check_if_present(table) is False:
                table += 1
        ms.scheme.append((ms.metadata_table_names[table], table, mtsh.Rows[index]))
    return ms


def find_signature(dd, signature):
    """
    Signature: It's a simple DWORD-signature (similar to the ones you find in
    the DOS Header and the Optional Header). Anyway, the value of this signature
    has to be 0x424A5342. 
    """
    metadata_offset = dd.find(signature)
    if metadata_offset is -1:
        return None
    return metadata_offset


def run(ff):
    # TODO: save data as JSON. Can modify variable names and parse out all variable that contain "_"
    image_file_header = get_image_file_header(ff)
    if image_file_header:
        image_optional_header = get_image_optional_header(ff, image_file_header._offset)
        if image_optional_header is None:
            return None
        image_section_headers = []
        section_addr = image_optional_header.end
        for sections in range(0, image_file_header.NumberOfSections):
            image_section_headers.append(read_image_section_header(ff, section_addr))
            section_addr += 40
        # TODO Check name. .text might not be the first entry!
        image_cor20_header = read_common_language_runtime_header(ff, image_section_headers[0].PointerToRawData + 8)
        # TODO  add check if StrongNameSignature is present
        # parse out StrongNameSignature
        signature_file_offset = image_section_headers[0].PointerToRawData - image_section_headers[0].VirtualAddress +\
                                image_cor20_header.StrongNameSignature.VirtualAddress
        strong_name_signature = []
        for byte in ff[signature_file_offset : signature_file_offset + image_cor20_header.StrongNameSignature.Size]:
            strong_name_signature.append(byte)
        if image_optional_header:
            # TODO below....
            if True is not None:
                # .text section is the first section
                meta_header_offset = image_section_headers[0].PointerToRawData - image_section_headers[0].VirtualAddress \
                                     + image_cor20_header.MetaData.VirtualAddress
                mh = read_metadata_header(meta_header_offset, ff)
                if mh is None:
                    print "Metadata signature not found"
                    return None
                for stream in mh.StreamHeaders:
                    # TODO: remove debug print
                     #print stream.name, hex(stream.size), hex(stream.offset + mh.offset)
                    if "#~" in stream.name or "#-" in stream.name:
                        # #~: A compressed (optimized) metadata stream. This stream contains an optimized system of
                        # metadata tables.
                        # #-: An uncompressed (unoptimized) metadata stream
                        optimized = False
                        if "#~" in stream.name:
                            optimized = True
                        metadata_table_stream_header = read_metadata_table_stream_header(stream.offset + mh.offset, ff)
                        metadata_scheme = create_metadata_table(metadata_table_stream_header, optimized)
                        for scheme in metadata_scheme.scheme:
                            print scheme
                        print hex(metadata_table_stream_header._end)
        get_metadata_scheme(0,0)

# main 
f = open(r"test_bins\System.Reflection.context.dll", 'rb')
g = open(r"test_bins\CrackMe4-Signed.ex_", "rb")
d = f.read()
h = g.read()
run(d)
run(h)
