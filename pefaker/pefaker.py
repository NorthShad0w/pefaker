from PIL import Image
import lief
import sys
import numpy as np

# for debug nice print
np.set_printoptions(formatter={'int': hex})

# convert png to ico
def parse_png(png_location, out_put_location, height: int, width: int):
    img = Image.open(png_location).resize((height, width))
    saved_filename = out_put_location + f"{height}-{width}.ico"
    img.save(saved_filename, size=[(height, width)])
    return saved_filename

# get a ResourceIcon class template
def get_icon_template():
    binary = lief.parse("test/calc.exe")
    return binary.resources_manager.icons[0]

# sync properties
def set_up_new_icon_by_old_icon(icon,icon_template):
    new_icon = icon_template
    new_icon.bit_count = icon.bit_count
    new_icon.color_count = icon.color_count
    new_icon.height = icon.height
    new_icon.id = icon.id
    new_icon.lang = icon.lang
    new_icon.planes = icon.planes
    new_icon.sublang = icon.sublang
    new_icon.width = icon.width
    return new_icon


def change_pe_resource(origin_pe, modified_pe, png_location):
    binary = lief.parse(origin_pe)
    if binary.has_resources:
        print("binary has resources, proceed.")
    else:
        sys.exit(1)

    root = binary.resources

    # ico_nodes = root.childs[0].childs

    # f =  open(ico_location,"rb")
    # ico_b = f.read()
    # for i in ico_nodes:
    #     i.childs[0].content = list(ico_b)
    # f.close()

    # TODO 判断给定图像和原来的大小
    # TODO 原本无icon的exe加icon

    resources_manager = binary.resources_manager
    icon_template = get_icon_template()
    if resources_manager.has_icons:
        print("the pe itself has icon")
        icon_group = root.childs[1].childs[0].childs[0].content
        for icon in resources_manager.icons:
            # handle the situation height == 256 (0)
            if icon.height == 0:
                print(icon.id,icon.height,icon.width)
                new_icon = set_up_new_icon_by_old_icon(icon,icon_template)
                new_ico_location = parse_png(png_location,"test/",256,256)
            else:
                print(icon.id,icon.height,icon.width)
                new_icon = set_up_new_icon_by_old_icon(icon,icon_template)
                new_ico_location = parse_png(png_location,"test/",new_icon.height,new_icon.width)

            with open(new_ico_location, "rb") as f:
                ico_bytes = f.read()
                print(len(list(ico_bytes)),len(icon.pixels))
                new_icon.pixels = list(ico_bytes)
            
            print(icon.id, new_icon.id)
            resources_manager.change_icon(icon,new_icon)
            # restore icon group
            root.childs[1].childs[0].childs[0].content = icon_group
    else:
        print("the pe don't have icon")
        resources_manager.add_icon(icon_template)




    manifest = resources_manager.manifest

    resources_manager.manifest = manifest

    builder = lief.PE.Builder(binary)
    builder.build_resources(True)

    builder.build()
    builder.write(modified_pe)
    return 0


def change_pe_menifest_infomation(origin_pe, modified_pe, new_author, new_creation_time, new_last_modify_time):
    binary = lief.parse(origin_pe)

    builder = lief.PE.Builder(binary)

    builder.build()
    builder.write(modified_pe)
    return 0


def change_pe_signature():

    return 0


def main():
    # set up test arguments here
    origin_pe = "test/no.exe"
    modified_pe = "test/new.exe"

    png_location = "test/PDF-origin.png"

    new_author = "administrator00001"
    new_creation_time = "2000.01.01"
    new_last_modify_time = "2000.01.01"

    # result = parse_png("test/PDF-origin.png", "test/", 48,48)
    # print(result)
    change_pe_resource(origin_pe,
                       modified_pe, png_location)
    # change_pe_meta_infomation(
    #     origin_pe, modified_pe, new_author, new_creation_time, new_last_modify_time)
    # change_pe_menifest_infomation()
    # change_pe_signature()


if __name__ == '__main__':
    main()
