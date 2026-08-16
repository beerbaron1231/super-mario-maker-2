import struct

# S->C 0x73.70 response (576 bytes)
hex_data = '020000001b0100000016010000f7030000000000001400303030302d303030302d303346372d394445300001d2496b000000000a007465737420736d6231000a00736d623120746573740000007a6d1faa1f00000005010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000310068747470733a2f2f3139322e3136382e312e3134373a36303037382f72656c6174696f6e2f7468756d62315f31303135000000c00100000000000c007468756d62315f3130313500310068747470733a2f2f3139322e3136382e312e3134373a36303037382f72656c6174696f6e2f7468756d62325f313031350000810a0000000000000c007468756d62325f3130313500150100000010010000f6030000000000001400303030302d303030302d303346362d394444460001d2496b000000000700746573742037000700372074657374000000ca6b1faa1f00000005010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000310068747470733a2f2f3139322e3136382e312e3134373a36303037382f72656c6174696f6e2f7468756d62315f31303134000000c00100000000000c007468756d62315f3130313400310068747470733a2f2f3139322e3136382e312e3134373a36303037382f72656c6174696f6e2f7468756d62325f313031340000bb090000000000000c007468756d62325f313031340000000000'

data = bytes.fromhex(hex_data)
print(f'Total response: {len(data)} bytes')
print()

def rd_u8(b, i):
    return b[i], i+1
def rd_u16(b, i):
    return struct.unpack_from('<H', b, i)[0], i+2
def rd_u32(b, i):
    return struct.unpack_from('<I', b, i)[0], i+4
def rd_u64(b, i):
    return struct.unpack_from('<Q', b, i)[0], i+8
def rd_str(b, i):
    n, i = rd_u16(b, i)
    s = b[i:i+n]; i += n
    return s, i
def rd_qbuf(b, i):
    n, i = rd_u16(b, i)
    buf = b[i:i+n]; i += n
    return buf, i
def rd_map_u8u32(b, i):
    n, i = rd_u32(b, i)
    m = {}
    for k in range(n):
        kk, i = rd_u8(b, i)
        vv, i = rd_u32(b, i)
        m[kk] = vv
    return m, i

# Parse 1st CourseInfo
i = 0
count, i = rd_u32(data, i)
print(f'list<CourseInfo> count = {count}')

for course_idx in range(count):
    print(f'\n--- CourseInfo #{course_idx+1} ---')
    elem_len, i = rd_u32(data, i)
    print(f'  element length (outer): {elem_len}')

    # frameStruct
    version, i = rd_u8(data, i)
    print(f'  version: {version}')
    inner_len, i = rd_u32(data, i)
    print(f'  inner length: {inner_len}')

    body_start = i
    # Parse CourseInfo fields
    data_id, i = rd_u64(data, i)
    print(f'  data_id u64: {data_id} (0x{data_id:x})')

    code, i = rd_str(data, i)
    print(f'  code string: {code!r}')

    # owner_id: try u32 first
    if i + 4 <= len(data):
        v32, _ = rd_u32(data, i)
        print(f'  owner_id as u32: 0x{v32:08x} = {v32}')

    # Read what's there
    pos_owner = i
    owner_bytes = data[i:i+8]
    print(f'  owner_id raw bytes: {" ".join(f"{b:02x}" for b in owner_bytes)}')

    # Read as u32
    owner_u32, i_u32 = rd_u32(data, i)
    print(f'    as u32: 0x{owner_u32:08x} = {owner_u32}')
    # After u32
    next_after_u32 = data[i_u32:i_u32+10]
    print(f'    next 10 bytes after u32: {" ".join(f"{b:02x}" for b in next_after_u32)}')

    # Read as u64
    owner_u64, i_u64 = rd_u64(data, i)
    print(f'    as u64: 0x{owner_u64:016x} = {owner_u64}')
    next_after_u64 = data[i_u64:i_u64+10]
    print(f'    next 10 bytes after u64: {" ".join(f"{b:02x}" for b in next_after_u64)}')

    # Try u32
    i = i_u32
    name, i = rd_str(data, i)
    print(f'  (u32 owner) name: {name!r}')
    desc, i = rd_str(data, i)
    print(f'  (u32 owner) desc: {desc!r}')
