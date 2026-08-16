import struct

# 68 body (172 bytes) for "smw forest night no jump" / data_id=1012
body = bytes.fromhex('05003130313200050031303132000500313031320001000005003130313200f40300000000000000800000001900736d7720666f72657374206e69676874206e6f206a756d70000400736d770001000000010209050000002000000005000000400600003000975a9ed4189dd649115f39c28fba43b315c4a754cd86d9c100949779e823ca096da4f8689eaa0a898fcbc6400a4d3f6a03e67a3208000000000000c005004000000000000000')
print(f'Body length: {len(body)} bytes')
print()

def rd_u16(b, i):
    return struct.unpack_from('<H', b, i)[0], i+2
def rd_u32(b, i):
    return struct.unpack_from('<I', b, i)[0], i+4
def rd_u64(b, i):
    return struct.unpack_from('<Q', b, i)[0], i+8
def rd_str(b, i):
    (n,) = struct.unpack_from('<H', b, i); i += 2
    s = b[i:i+n]; i += n
    return s, i
def rd_u8(b, i):
    return b[i], i+1

i = 0
print('--- 4x data_id_strs ---')
for k in range(4):
    s, i = rd_str(body, i)
    print(f'  data_id_str[{k}]: {s!r}')
data_id, i = rd_u64(body, i)
print(f'  data_id u64: {data_id} (0x{data_id:x})')

print()
print('--- Pre-name metadata ---')
v, i = rd_u32(body, i); print(f'  u32: 0x{v:08x} = {v}')
v, i = rd_u32(body, i); print(f'  u32: 0x{v:08x} = {v}')
v, i = rd_u16(body, i); print(f'  u16: 0x{v:04x} = {v}')

print()
print('--- name + desc ---')
s, i = rd_str(body, i); print(f'  name: {s!r}')
s, i = rd_str(body, i); print(f'  desc: {s!r}')

print()
print('--- Post-name metadata, byte-by-byte from current pos ---')
start = i
print(f'  starting at pos {start}')
print(f'  next 60 bytes raw:')
print('   ', ' '.join(f'{b:02x}' for b in body[i:i+60]))

print()
print('--- As u8s ---')
for k in range(20):
    if i+k >= len(body): break
    print(f'  pos {i+k}: u8 = {body[i+k]}')

print()
print('--- As u16s ---')
for k in range(15):
    j = i + k*2
    if j+2 > len(body): break
    v = struct.unpack_from('<H', body, j)[0]
    print(f'  pos {j}: u16 = 0x{v:04x} = {v}')

print()
print('--- As u32s ---')
for k in range(10):
    j = i + k*4
    if j+4 > len(body): break
    v = struct.unpack_from('<I', body, j)[0]
    print(f'  pos {j}: u32 = 0x{v:08x} = {v}')
