#!/usr/bin/env python

# pip install pe_tools lief 
# debian:
# sudo apt install mingw-w64 
# centos:
# sudo dnf install mingw-w64 

# Usage: python pefaker/pefaker.py

import sys
import os
import lief
import grope
from pe_tools.pe_parser import parse_pe, IMAGE_DIRECTORY_ENTRY_RESOURCE
from pe_tools.rsrc import pe_resources_prepack, parse_prelink_resources, KnownResourceTypes


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
    resources = {k: v for k, v in resources.items() if k == RT_MANIFEST}

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


def change_pe_resource(origin_pe, modified_pe):
    binary = lief.parse(origin_pe)
    if binary.has_resources:
        print("binary has resources, proceed.")
    else:
        sys.exit(1)

    resources_manager = binary.resources_manager
    resources_manager.manifest = """<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level='asInvoker' uiAccess='false' />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"""

    builder = lief.PE.Builder(binary)
    builder.build_resources(True)

    builder.build()
    builder.write(modified_pe)

def compile_res_file(ico_file):
    rc_content = f"""ICON1               ICON                    "{ico_file}"
    """
    with open("test/pdf.rc","w") as f:
        f.write(rc_content)

    print("rc file writen.")

    # install 
    # sudo apt install mingw-w64 / sudo dnf install mingw-w64 
    os.system("x86_64-w64-mingw32-windres -r -i test/pdf.rc -o test/newpdf.res")
    print("res file generated")

    res_file = "test/newpdf.res"
    return res_file

def main():
    # set up test arguments here
    origin_pe = "test/calc.exe"
    modified_pe = "test/newcalc.exe"

    # TODO generate xxx.res with xxx.ico file

    ico_file = "test/PDF.ico"

    # res_file = "test/pdf.res"
    res_file = ""

    if len(res_file) == 0:
        print("res file not defined")
        if len(ico_file) > 0 :
            res_file = compile_res_file(ico_file)

    # new_author = "administrator00001"
    # new_creation_time = "2000.01.01"
    # new_last_modify_time = "2000.01.01"

    pe, resources = parse_input_file(origin_pe)

    modified_resources = clear_all_resources(resources)

    modified_resources = add_pdf_icon(res_file, modified_resources)

    prepacked = pe_resources_prepack(modified_resources)
    addr = pe.resize_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, prepacked.size)
    pe.set_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, prepacked.pack(addr))

    with open(modified_pe, 'wb') as fout:
        grope.dump(pe.to_blob(), fout)

    change_pe_resource(modified_pe, modified_pe)
    print("finished:", modified_pe)


if __name__ == '__main__':
    main()
