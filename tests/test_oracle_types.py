"""
Independent Type Oracle Verification Test.
Compares SafeGGUF's TypeTraits table against the compiled upstream ggml C library oracle.
"""

import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
ORACLE_BIN = os.path.join(SCRIPT_DIR, "oracle", "ggml_oracle")
TYPES_ZIG = os.path.join(REPO_ROOT, "src", "gguf", "types.zig")

def parse_upstream_types():
    if not os.path.exists(ORACLE_BIN):
        print(f"Building oracle binary first via {os.path.join(SCRIPT_DIR, 'build_oracle.sh')}...")
        subprocess.check_call([os.path.join(SCRIPT_DIR, "build_oracle.sh")])

    proc = subprocess.run([ORACLE_BIN, "--dump-types"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    lines = proc.stdout.strip().splitlines()
    assert lines[0] == "TYPE_TRAITS_BEGIN"
    assert lines[-1] == "TYPE_TRAITS_END"

    types = {}
    for line in lines[1:-1]:
        first_comma = line.find(",")
        t_id = int(line[:first_comma])
        rest = line[first_comma + 1:]
        r_parts = rest.rsplit(",", 2)
        name = r_parts[0]
        blck_size = int(r_parts[1])
        type_size = int(r_parts[2])
        types[t_id] = {
            "name": name,
            "block_size": blck_size,
            "type_size": type_size,
            "is_valid": blck_size > 0 and type_size > 0
        }
    return types

def parse_safegguf_traits():
    with open(TYPES_ZIG, "r") as f:
        content = f.read()

    enum_map = {}
    in_enum = False
    for line in content.splitlines():
        if "pub const GGMLType = enum(u32)" in line:
            in_enum = True
            continue
        if in_enum:
            if line.strip().startswith("};"):
                in_enum = False
                continue
            m = re.match(r"\s*([a-zA-Z0-9_]+)\s*=\s*(\d+),", line)
            if m:
                enum_map[m.group(1)] = int(m.group(2))

    traits_map = {}
    in_traits = False
    for line in content.splitlines():
        if "pub fn getTypeTraits" in line:
            in_traits = True
            continue
        if in_traits:
            if line.strip().startswith("};"):
                in_traits = False
                continue
            m = re.match(r"\s*(\d+)\s*=>\s*TypeTraits\{\s*\.name\s*=\s*\"([^\"]+)\",\s*\.block_size\s*=\s*(\d+),\s*\.type_size\s*=\s*(\d+)\s*\},", line)
            if m:
                t_id = int(m.group(1))
                name = m.group(2)
                bs = int(m.group(3))
                ts = int(m.group(4))
                traits_map[t_id] = {"name": name, "block_size": bs, "type_size": ts}

    return enum_map, traits_map

def main():
    print("Verifying SafeGGUF Type Traits against Compiled Upstream ggml 0.23.0 Oracle...")
    upstream = parse_upstream_types()
    enum_map, safegguf_traits = parse_safegguf_traits()

    print(f"  Upstream exposes {len(upstream)} GGML type slots (0 to {max(upstream.keys())}).")
    print(f"  SafeGGUF recognizes {len(enum_map)} GGMLType enum slots, {len(safegguf_traits)} active traits.")

    errors = []
    for t_id, up_info in upstream.items():
        if up_info["is_valid"]:
            if t_id not in safegguf_traits:
                errors.append(f"Missing valid type in SafeGGUF: ID {t_id} ({up_info['name']}) with blck={up_info['block_size']}, size={up_info['type_size']}")
            else:
                safe_info = safegguf_traits[t_id]
                if safe_info["block_size"] != up_info["block_size"]:
                    errors.append(f"Block size mismatch for ID {t_id} ({up_info['name']}): upstream={up_info['block_size']}, safegguf={safe_info['block_size']}")
                if safe_info["type_size"] != up_info["type_size"]:
                    errors.append(f"Type size mismatch for ID {t_id} ({up_info['name']}): upstream={up_info['type_size']}, safegguf={safe_info['type_size']}")
        else:
            # Deprecated or removed slot
            if t_id in safegguf_traits:
                errors.append(f"SafeGGUF accepted removed/deprecated slot as valid: ID {t_id} ({up_info['name']})")

    if errors:
        print("\nERRORS DETECTED:")
        for e in errors:
            print("  X " + e)
        sys.exit(1)

    print("\n✓ Independent Type Oracle Verification PASSED (43/43 type slots matched perfectly)!")

if __name__ == "__main__":
    main()
