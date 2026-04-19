import argparse
import ctypes.util
import pefile    

def grab_exports(dll):
    dll_path = ctypes.util.find_library(dll)
    pe = pefile.PE(dll_path)

    # Key = name, value = ordinal
    exports = {}
    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        exports[export.name.decode()] = export.ordinal

    return exports

# Format: #pragma comment(linker, "/export:FunctionName=OriginalDLL.FunctionName,@ordinal")
def generate_pragmas(dll, exports):
    pragmas = []
    for name, ordinal in exports.items():
        pragmas.append(f'#pragma comment(linker, "/export:{name}={dll}.{name},@{ordinal}")')
    
    return pragmas

def parse_args():
    parser = argparse.ArgumentParser(description="Generate C/C++ #pragma comments to proxy DLL exports for sideloading")
    parser.add_argument('-dll', help="DLL Name", required=True)
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    export = grab_exports(args.dll)
    pragma = generate_pragmas(args.dll, export)

    for p in pragma:
        print(p)
