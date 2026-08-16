import struct

# 1st 68 body (test 6, 157 bytes) — extract post-name+desc
b1_full = bytes.fromhex('05003130313100050031303131000500313031310001000005003130313100f3030000000000000071000000070074657374203600070036207465737400010000000100000500000020000000050000001a08000030007063474318b19889fda698fb72272afd488ff942f66e247f1545e8e1c209415d377662e386768692176615b24d83a55c0000000000000000000000c005004000000000000000')
# 2nd 68 body (smw forest night no jump, 172 bytes)
b2_full = bytes.fromhex('05003130313200050031303132000500313031320001000005003130313200f40300000000000000800000001900736d7720666f72657374206e69676874206e6f206a756d70000400736d770001000000010209050000002000000005000000400600003000975a9ed4189dd649115f39c28fba43b315c4a754cd86d9c100949779e823ca096da4f8689eaa0a898fcbc6400a4d3f6a03e67a3208000000000000c005004000000000000000')

# 1st 68: 3*7 (3 strs) + 10 (4th str w/ u16 1 + u8 0) + 8 (u64) + 10 (u32 0 + u32 0x7100 + u16 0) + 2+7 (name) + 2+7 (desc) = 67
# 2nd 68: same structure but name=25 desc=4 → 3*7 + 10 + 8 + 10 + 2+25 + 2+4 = 82
# Wait, also pre-name metadata is u32 0x8000 for 2nd, not 0x7100. Same SIZE though.
# 1st: name "test 6" (7) desc "6 test" (7)
# 2nd: name "smw forest night no jump" (25) desc "smw" (4)
b1_post = b1_full[65:]  # post-name+desc: u32 0 + u32 0x71 + u16 7 + name(7) + u16 7 + desc(7) = 10+9+7+2+7=... let me recount: pos 39-42 u32 0, pos 43-46 u32 0x71, pos 47-48 u16 7, pos 49-55 name, pos 56-57 u16 7, pos 58-64 desc. End of name+desc = 65.
b2_post = b2_full[80:]  # pos 39-42 u32 0, pos 43-46 u32 0x80, pos 47-48 u16 25, pos 49-73 name, pos 74-75 u16 4, pos 76-79 desc. End = 80.

# Debug: print the actual bytes around the offsets
print(f'  1st body pos 60-72: {" ".join(f"{b:02x}" for b in b1_full[60:72])}')
print(f'  1st body pos 65-85: {" ".join(f"{b:02x}" for b in b1_full[65:85])}')
print(f'  2nd body pos 75-90: {" ".join(f"{b:02x}" for b in b2_full[75:90])}')
print(f'  2nd body pos 80-100: {" ".join(f"{b:02x}" for b in b2_full[80:100])}')
print(f'1st 68 post-name+desc: {len(b1_post)} bytes')
print(f'2nd 68 post-name+desc: {len(b2_post)} bytes')
print()

L = min(len(b1_post), len(b2_post))
print(f'Diffing first {L} bytes:')
print('  pos | b1 | b2 | diff?')
print(f'  b1_post[0..15] = {" ".join(f"{b:02x}" for b in b1_post[:16])}')
print(f'  b2_post[0..15] = {" ".join(f"{b:02x}" for b in b2_post[:16])}')
for i in range(L):
    a, c = b1_post[i], b2_post[i]
    if a != c:
        sa = chr(a) if 32 <= a < 127 else '.'
        sc = chr(c) if 32 <= c < 127 else '.'
        print(f'  {i:4d} | {a:02x} | {c:02x} |  !    | {sa} | {sc}')

print()
print('Trailing bytes (1st only):')
if len(b1_post) > L:
    print(f'  1st: {" ".join(f"{b:02x}" for b in b1_post[L:])}')
print('Trailing bytes (2nd only):')
if len(b2_post) > L:
    print(f'  2nd: {" ".join(f"{b:02x}" for b in b2_post[L:])}')

# Sanity: verify name+desc parsing
def parse_str(b, i):
    (n,) = struct.unpack_from('<H', b, i); i += 2
    s = b[i:i+n]; i += n
    return s, i

i = 0
for k in range(3):
    s, i = parse_str(b1_full, i)
    print(f'  1st 68 data_id_str[{k}]: {s!r}')

# 4th str: u16 1, u8 0, u16 5, "1011\0"
v16 = struct.unpack_from('<H', b1_full, i)[0]; i += 2
v8 = b1_full[i]; i += 1
v16b = struct.unpack_from('<H', b1_full, i)[0]; i += 2
s = b1_full[i:i+v16b]; i += v16b
print(f'  1st 68 4th str: u16 1, u8 0, u16 {v16b}, {s!r}')

# u64
data_id = struct.unpack_from('<Q', b1_full, i)[0]; i += 8
print(f'  1st 68 data_id u64: {data_id} (0x{data_id:x})')

# pre-name metadata
v32_1 = struct.unpack_from('<I', b1_full, i)[0]; i += 4
v32_2 = struct.unpack_from('<I', b1_full, i)[0]; i += 4
v16_3 = struct.unpack_from('<H', b1_full, i)[0]; i += 2
print(f'  1st 68 pre-name: u32 0x{v32_1:x}, u32 0x{v32_2:x}, u16 0x{v16_3:x}')

# name
s, i = parse_str(b1_full, i)
print(f'  1st 68 name: {s!r}')
s, i = parse_str(b1_full, i)
print(f'  1st 68 desc: {s!r}')
print(f'  1st 68 end of name+desc: pos {i}')

# 2nd 68
i = 0
for k in range(3):
    s, i = parse_str(b2_full, i)
    print(f'  2nd 68 data_id_str[{k}]: {s!r}')

v16 = struct.unpack_from('<H', b2_full, i)[0]; i += 2
v8 = b2_full[i]; i += 1
v16b = struct.unpack_from('<H', b2_full, i)[0]; i += 2
s = b2_full[i:i+v16b]; i += v16b
print(f'  2nd 68 4th str: u16 1, u8 0, u16 {v16b}, {s!r}')

data_id = struct.unpack_from('<Q', b2_full, i)[0]; i += 8
print(f'  2nd 68 data_id u64: {data_id} (0x{data_id:x})')

v32_1 = struct.unpack_from('<I', b2_full, i)[0]; i += 4
v32_2 = struct.unpack_from('<I', b2_full, i)[0]; i += 4
v16_3 = struct.unpack_from('<H', b2_full, i)[0]; i += 2
print(f'  2nd 68 pre-name: u32 0x{v32_1:x}, u32 0x{v32_2:x}, u16 0x{v16_3:x}')

s, i = parse_str(b2_full, i)
print(f'  2nd 68 name: {s!r}')
s, i = parse_str(b2_full, i)
print(f'  2nd 68 desc: {s!r}')
print(f'  2nd 68 end of name+desc: pos {i}')
