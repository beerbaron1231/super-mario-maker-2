import struct, sys

raw = '008a000000070074657374203600070036207465737400010000000100000500000020000000050000001a08000030007063474318b19889fda698fb72272afd488ff942f66e247f1545e8e1c209415d377662e386768692176615b24d83a55c0000000000000000000000c0050040000000060000000800556e6b6e6f776e00010000010000010000010000010000'
print(f'Full hex char count: {len(raw)} = {len(raw)//2} bytes')
print(f'Header (5 bytes = 10 hex): {raw[:10]}')
body_hex = raw[10:]
print(f'Body: {len(body_hex)} hex chars = {len(body_hex)//2} bytes')
body = bytes.fromhex(body_hex)
print(f'First 30 bytes:')
for i in range(min(30, len(body))):
    ch = chr(body[i]) if 32 <= body[i] < 127 else '.'
    print(f'  pos {i:3d}: 0x{body[i]:02x} ({body[i]:3d}) {ch}')

print()
print('=== Test A: ORIGINAL parse (name, desc, tagCount, tags, style, theme, diff) ===')
i = 0
try:
    (n,) = struct.unpack_from('<I', body, i); i += 4
    name = body[i:i+n]; i += n
    print(f'  name: len={n} value={name!r}')
    (n,) = struct.unpack_from('<I', body, i); i += 4
    desc = body[i:i+n]; i += n
    print(f'  desc: len={n} value={desc!r}')
    (tag_count,) = struct.unpack_from('<I', body, i); i += 4
    print(f'  tag_count: {tag_count} (0x{tag_count:x})')
    if tag_count <= 8:
        for t in range(tag_count):
            print(f'  tag[{t}]: {body[i]}'); i += 1
    print(f'  game_style (u8): {body[i]}'); i += 1
    print(f'  course_theme (u8): {body[i]}'); i += 1
    print(f'  difficulty (u8): {body[i]}'); i += 1
    print(f'  consumed {i} bytes, remaining {len(body)-i}')
except Exception as e:
    print(f'  PARSE FAILED at offset {i}: {e}')
    print(f'  remaining bytes: {body[i:i+30].hex()}')

print()
print('=== Test B: 2 strings + 30 raw bytes dump ===')
i = 0
(n,) = struct.unpack_from('<I', body, i); i += 4
name = body[i:i+n]; i += n
print(f'  name at pos 0, len={n}: {name!r}')
(n,) = struct.unpack_from('<I', body, i); i += 4
desc = body[i:i+n]; i += n
print(f'  desc at pos {i-4-n}, len={n}: {desc!r}')
print(f'  Next 30 bytes (pos {i}):')
print('    ' + ' '.join(f'{b:02x}' for b in body[i:i+30]))

print()
print('=== Test C: After 2 strings, treat next 4 bytes as u32 (looking for tag count or similar) ===')
j = i
for off in range(0, 24, 4):
    if j+off+4 > len(body): break
    (v,) = struct.unpack_from('<I', body, j+off)
    print(f'  u32 at pos {j+off}: {v} (0x{v:08x})')
