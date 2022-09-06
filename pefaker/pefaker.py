#!/usr/bin/env python

# pip install pe_tools lief
# debian:
# sudo apt install mingw-w64
# centos:
# sudo dnf install mingw-w64

# Usage: python pefaker/pefaker.py

import re
import sys
import os
import lief
import grope
import struct
import shutil
import io
from pe_tools.pe_parser import parse_pe, IMAGE_DIRECTORY_ENTRY_RESOURCE
from pe_tools.rsrc import pe_resources_prepack, parse_prelink_resources, KnownResourceTypes
from pe_tools.version_info import parse_version_info, VersionInfo


class Version:
    def __init__(self, s):
        parts = s.split(',')
        if len(parts) == 1:
            parts = parts[0].split('.')
        self._parts = [int(part.strip()) for part in parts]
        if not self._parts or len(self._parts) > 4 or any(part < 0 or part >= 2**16 for part in self._parts):
            raise ValueError('invalid version')

        while len(self._parts) < 4:
            self._parts.append(0)

    def get_ms_ls(self):
        ms = (self._parts[0] << 16) + self._parts[1]
        ls = (self._parts[2] << 16) + self._parts[3]
        return ms, ls

    def format(self):
        return ', '.join(str(part) for part in self._parts)


class _IdentityReplace:
    def __init__(self, val):
        self._val = val

    def __call__(self,s):
        return self._val


class _ReReplace:
    def __init__(self, compiled_re, sub):
        self._compiled_re = compiled_re
        self._sub = sub

    def __call__(self, s):
        return self._compiled_re.sub(self._sub, s)


RT_VERSION = KnownResourceTypes.RT_VERSION
RT_MANIFEST = KnownResourceTypes.RT_MANIFEST


def parse_input_file(origin_pe):
    fin = open(origin_pe, 'rb')
    pe = parse_pe(grope.wrap_io(fin))
    resources = pe.parse_resources()

    if resources is None:
        resources = {}

    return pe, resources


def clear_all_resources(resources):
    resources = {k: v for k, v in resources.items() if k == RT_MANIFEST or k == RT_VERSION}

    return resources


def add_pdf_icon(res_file, resources):
    res_fin = open(res_file, 'rb')
    # must not close res_fin until the ropes are gone

    r = parse_prelink_resources(grope.wrap_io(res_fin))
    for resource_type in r:
        for name in r[resource_type]:
            for lang in r[resource_type][name]:
                resources.setdefault(resource_type, {}).setdefault(
                    name, {})[lang] = r[resource_type][name][lang]

    return resources


def change_pe_manifest(origin_pe, modified_pe):
    binary = lief.parse(origin_pe)
    if binary.has_resources:
        print("binary has resources, proceed.")
    else:
        sys.exit(1)

    resources_manager = binary.resources_manager
    resources_manager.manifest = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<assemblyIdentity
    name="Microsoft.Windows.Shell.calc"
    processorArchitecture="amd64"
    version="5.1.0.0"
    type="win32"/>
<description>Windows Shell</description>
<dependency>
    <dependentAssembly>
        <assemblyIdentity
            type="win32"
            name="Microsoft.Windows.Common-Controls"
            version="6.0.0.0"
            processorArchitecture="*"
            publicKeyToken="6595b64144ccf1df"
            language="*"
        />
    </dependentAssembly>
</dependency>
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
            <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
        </requestedPrivileges>
    </security>
</trustInfo>
<application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
        <dpiAware  xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
    </windowsSettings>
</application>
</assembly>
"""

    builder = lief.PE.Builder(binary)
    builder.build_resources(True)

    builder.build()
    builder.write(modified_pe)


def change_version_infomation(values_to_set, resources):
    modified_resources = resources
    ver_data = None
    for name in modified_resources.get(RT_VERSION, ()):
        print(name)
        for lang in modified_resources[RT_VERSION][name]:
            if ver_data is not None:
                print('error: multiple manifest resources found', file=sys.stderr)
                return 4
            ver_data = modified_resources[RT_VERSION][name][lang]
            ver_name = name
            ver_lang = lang

    if ver_data is None:
        print("Ver_data is None")
        ver_data = VersionInfo()

    for i in values_to_set:
        values_to_set[i] = _IdentityReplace(values_to_set[i])
    
    version_info = parse_version_info(ver_data)
    fixed_version_info = version_info.get_fixed_info()
    if 'FileVersion' in values_to_set:
        ver = Version(values_to_set['FileVersion'](None))
        fixed_version_info.dwFileVersionMS, fixed_version_info.dwFileVersionLS = ver.get_ms_ls()
    if 'ProductVersion' in values_to_set:
        ver = Version(values_to_set['ProductVersion'](None))
        fixed_version_info.dwProductVersionMS, fixed_version_info.dwProductVersionLS = ver.get_ms_ls()
    version_info.set_fixed_info(fixed_version_info)

    string_file_info = version_info.string_file_info()
    for _, strings in string_file_info.items():
        for k, fn in values_to_set.items():
            val = fn(strings.get(k, ''))
            if val:
                strings[k] = val
            elif k in strings:
                del strings[k]
    version_info.set_string_file_info(string_file_info)
    modified_resources[RT_VERSION][ver_name][ver_lang] = version_info.pack()

    return modified_resources


def compile_res_file(ico_file):
    rc_content = f"""ICON1               ICON                    "{ico_file}"
    """
    with open("test/pdf.rc", "w") as f:
        f.write(rc_content)

    print("rc file writen.")

    # install
    # sudo apt install mingw-w64 / sudo dnf install mingw-w64
    os.system("x86_64-w64-mingw32-windres -r -i test/pdf.rc -o test/newpdf.res")
    print("res file generated")

    res_file = "test/newpdf.res"
    return res_file

def gather_file_info_win(binary):
        """
        Borrowed from BDF...
        I could just skip to certLOC... *shrug*
        """
        flItms = {}
        binary = open(binary, 'rb')
        binary.seek(int('3C', 16))
        flItms['buffer'] = 0
        flItms['JMPtoCodeAddress'] = 0
        flItms['dis_frm_pehdrs_sectble'] = 248
        flItms['pe_header_location'] = struct.unpack('<i', binary.read(4))[0]
        # Start of COFF
        flItms['COFF_Start'] = flItms['pe_header_location'] + 4
        binary.seek(flItms['COFF_Start'])
        flItms['MachineType'] = struct.unpack('<H', binary.read(2))[0]
        binary.seek(flItms['COFF_Start'] + 2, 0)
        flItms['NumberOfSections'] = struct.unpack('<H', binary.read(2))[0]
        flItms['TimeDateStamp'] = struct.unpack('<I', binary.read(4))[0]
        binary.seek(flItms['COFF_Start'] + 16, 0)
        flItms['SizeOfOptionalHeader'] = struct.unpack('<H', binary.read(2))[0]
        flItms['Characteristics'] = struct.unpack('<H', binary.read(2))[0]
        #End of COFF
        flItms['OptionalHeader_start'] = flItms['COFF_Start'] + 20

        #if flItms['SizeOfOptionalHeader']:
            #Begin Standard Fields section of Optional Header
        binary.seek(flItms['OptionalHeader_start'])
        flItms['Magic'] = struct.unpack('<H', binary.read(2))[0]
        flItms['MajorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
        flItms['MinorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
        flItms['SizeOfCode'] = struct.unpack("<I", binary.read(4))[0]
        flItms['SizeOfInitializedData'] = struct.unpack("<I", binary.read(4))[0]
        flItms['SizeOfUninitializedData'] = struct.unpack("<I",
                                                               binary.read(4))[0]
        flItms['AddressOfEntryPoint'] = struct.unpack('<I', binary.read(4))[0]
        flItms['PatchLocation'] = flItms['AddressOfEntryPoint']
        flItms['BaseOfCode'] = struct.unpack('<I', binary.read(4))[0]
        if flItms['Magic'] != 0x20B:
            flItms['BaseOfData'] = struct.unpack('<I', binary.read(4))[0]
        # End Standard Fields section of Optional Header
        # Begin Windows-Specific Fields of Optional Header
        if flItms['Magic'] == 0x20B:
            flItms['ImageBase'] = struct.unpack('<Q', binary.read(8))[0]
        else:
            flItms['ImageBase'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SectionAlignment'] = struct.unpack('<I', binary.read(4))[0]
        flItms['FileAlignment'] = struct.unpack('<I', binary.read(4))[0]
        flItms['MajorOperatingSystemVersion'] = struct.unpack('<H',
                                                                   binary.read(2))[0]
        flItms['MinorOperatingSystemVersion'] = struct.unpack('<H',
                                                                   binary.read(2))[0]
        flItms['MajorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
        flItms['MinorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
        flItms['MajorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
        flItms['MinorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
        flItms['Win32VersionValue'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfImageLoc'] = binary.tell()
        flItms['SizeOfImage'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfHeaders'] = struct.unpack('<I', binary.read(4))[0]
        flItms['CheckSum'] = struct.unpack('<I', binary.read(4))[0]
        flItms['Subsystem'] = struct.unpack('<H', binary.read(2))[0]
        flItms['DllCharacteristics'] = struct.unpack('<H', binary.read(2))[0]
        if flItms['Magic'] == 0x20B:
            flItms['SizeOfStackReserve'] = struct.unpack('<Q', binary.read(8))[0]
            flItms['SizeOfStackCommit'] = struct.unpack('<Q', binary.read(8))[0]
            flItms['SizeOfHeapReserve'] = struct.unpack('<Q', binary.read(8))[0]
            flItms['SizeOfHeapCommit'] = struct.unpack('<Q', binary.read(8))[0]

        else:
            flItms['SizeOfStackReserve'] = struct.unpack('<I', binary.read(4))[0]
            flItms['SizeOfStackCommit'] = struct.unpack('<I', binary.read(4))[0]
            flItms['SizeOfHeapReserve'] = struct.unpack('<I', binary.read(4))[0]
            flItms['SizeOfHeapCommit'] = struct.unpack('<I', binary.read(4))[0]
        flItms['LoaderFlags'] = struct.unpack('<I', binary.read(4))[0]  # zero
        flItms['NumberofRvaAndSizes'] = struct.unpack('<I', binary.read(4))[0]
        # End Windows-Specific Fields of Optional Header
        # Begin Data Directories of Optional Header
        flItms['ExportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
        flItms['ExportTableSize'] = struct.unpack('<I', binary.read(4))[0]
        flItms['ImportTableLOCInPEOptHdrs'] = binary.tell()
        #ImportTable SIZE|LOC
        flItms['ImportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
        flItms['ImportTableSize'] = struct.unpack('<I', binary.read(4))[0]
        flItms['ResourceTable'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['ExceptionTable'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['CertTableLOC'] = binary.tell()
        flItms['CertLOC'] = struct.unpack("<I", binary.read(4))[0]
        flItms['CertSize'] = struct.unpack("<I", binary.read(4))[0]
        binary.close()
        return flItms

def signfile(exe, sigfile):
    flItms = gather_file_info_win(exe)
    
    cert = open(sigfile, 'rb').read()

    output = str(exe) + "_signed"

    shutil.copy2(exe, output)
    
    print("Output file: {0}".format(output))
    
    with open(exe, 'rb') as g:
        with open(output, 'wb') as f:
            f.write(g.read())
            f.seek(0)
            f.seek(flItms['CertTableLOC'], 0)
            f.write(struct.pack("<I", len(open(exe, 'rb').read())))
            f.write(struct.pack("<I", len(cert)))
            f.seek(0, io.SEEK_END)
            f.write(cert)
    print("Signature appended. \nFIN.")

def main():
    # set up test arguments here
    origin_pe = "test/calc.exe"
    modified_pe = "test/newcalc.exe"

    # TODO generate xxx.res with xxx.ico file

    ico_file = "test/PDF.ico"

    # res_file = "test/pdf.res"
    res_file = ""

    if len(res_file) == 0:
        print("resources file not defined")
        if len(ico_file) > 0:
            res_file = compile_res_file(ico_file)
    
    # fake_signature_file_here
    fake_signature = "test/microsoft.fake.sig"

    # args_here
    file_version = "1.0.0.1"
    product_version = "1.0.0.2"
    file_description = "fake_file_for_test"
    InternalName = "CALCFAKE"
    CompanyName = "Microsoft Corporation fake"
    LegalCopyright = "©Microsoft Corporation. All rights reserved. fake"
    origin_file_name = "calc.exe"
    ProductName = "Microsoft® Windows® Operating System fake"

    values_to_set = {"FileVersion": file_version,
                    "ProductVersion": product_version,
                    "FileDescription": file_description,
                    "InternalName": InternalName,
                    "CompanyName": CompanyName, 
                    "LegalCopyright": LegalCopyright,
                    "OriginalFilename": origin_file_name,
                    "ProductName":ProductName}

    # new_creation_time = "2000.01.01"
    # new_last_modify_time = "2000.01.01"

    pe, modified_resources = parse_input_file(origin_pe)

    modified_resources = clear_all_resources(modified_resources)

    modified_resources = add_pdf_icon(res_file, modified_resources)

    modified_resources = change_version_infomation(values_to_set,modified_resources)

    prepacked = pe_resources_prepack(modified_resources)
    addr = pe.resize_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, prepacked.size)
    pe.set_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, prepacked.pack(addr))

    with open(modified_pe, 'wb') as fout:
        grope.dump(pe.to_blob(), fout)

    change_pe_manifest(modified_pe, modified_pe)

    signfile(modified_pe, fake_signature)


if __name__ == '__main__':
    main()
