import struct

# 2nd 68 body (smw forest night no jump, 172 bytes)
b2 = bytes.fromhex('05003130313200050031303132000500313031320001000005003130313200f40300000000000000800000001900736d7720666f72657374206e69676874206e6f206a756d70000400736d770001000000010209050000002000000005000000400600003000975a9ed4189dd649115f39c28fba43b315c4a754cd86d9c100949779e823ca096da4f8689eaa0a898fcbc6400a4d3f6a03e67a3208000000000000c005004000000000000000')
# 3rd 66 body (smb3 sky no damage, 167 bytes)
b3 = bytes.fromhex('00a20000001300736d623320736b79206e6f2064616d616765001300736d623320736b79206e6f2064616d6167650001000000010108050000002000000005000000cb0b00003000f9d9463c01f2cbf6c0c6f5974d9d0ddb6d5581c65eabe9851a7efe3b2041b331af7b77b043600eee4339ee3e73727625035a516416000000000000c0050040000000060000000800556e6b6e6f776e00010000010000010000010000010000')

# b2 and b3 include the 5-byte header (version u8 + body_len u32).
# So the body starts at index 5.
# 2nd 68 body post-name+desc starts at body pos 80 → b2[5+80] = b2[85]
# 3rd 66 body post-name+desc starts at body pos 42 → b3[5+42] = b3[47]
b2_post = b2[5+80:]
b3_post = b3[5+42:]

print(f'2nd 68 post: {len(b2_post)} bytes')
print(f'3rd 66 post: {len(b3_post)} bytes')
print()

# Trim to common length
L = min(len(b2_post), len(b3_post))
print(f'Diffing first {L} bytes:')
print('  pos | 2nd | 3rd | note')
for i in range(L):
    a, c = b2_post[i], b3_post[i]
    if a != c:
        sa = chr(a) if 32 <= a < 127 else '.'
        sc = chr(c) if 32 <= c < 127 else '.'
        note = ''
        if i in (5, 6):
            note = '   <-- likely style/theme'
        print(f'  {i:4d} | {a:02x} | {c:02x} | {sa} | {sc}{note}')

print()
# Now show the layout assumption
print('HYPOTHESIS: u8 at pos 5 = game_style (0-based), u8 at pos 6 = course_theme (0-based per style)')
print(f'  2nd (smw + ???): game_style={b2_post[5]}, course_theme={b2_post[6]}')
print(f'  3rd (smb3 + sky): game_style={b3_post[5]}, course_theme={b3_post[6]}')
print()
print('  SMM2 game_style 0-based: 0=SMB1, 1=SMB3, 2=SMW, 3=NSMBU')
print('  SMM2 SMB3 themes 0-based: 0=Ground, 1=Underground, ..., 7=Desert, 8=Sky')
print('  SMM2 SMW themes 0-based: 0=Ground, 1=Underground, ..., 7=Desert, 8=Sky, 9=Forest, 10=Forest Night')
print()
print('  => 2nd course = SMW (2) + Forest (9) — NOT Forest Night as user said')
print('  => 3rd course = SMB3 (1) + Sky (8) — matches user')
print()

# Now find what other fields might exist
print('Looking for difficulty (0-3) in the post-name+desc region of 2nd 68 and 3rd 66:')
for i in range(min(40, L)):
    if b2_post[i] <= 3 and b3_post[i] <= 3 and b2_post[i] == b3_post[i]:
        print(f'  pos {i}: both = {b2_post[i]} (could be difficulty=Normal=1, both are Normal)')

# Check all bytes 0-30 that match between 2 and 3 (excluding the known diffs)
print()
print('Bytes 0-30 in 3rd 66 that match 2nd 68 (constants):')
constants = []
for i in range(min(30, L)):
    if b2_post[i] == b3_post[i]:
        constants.append((i, b3_post[i]))
print(f'  {len(constants)} matching positions in first 30 bytes:')
for pos, val in constants:
    print(f'    pos {pos}: 0x{val:02x}')

# Look at pos 7 which is same in both
print()
print(f'pos 7 in 2nd: {b2_post[7]:02x}, in 3rd: {b3_post[7]:02x} (both 0x05 — could be tag_count=5?)')
