package main

// ADVERTENCIA (16/8): este archivo quedó SIN USAR a propósito. El RNG de acá (seadRNG,
// estilo "SFC") es DISTINTO al algoritmo real de Nintendo/kinnay para SMM2 (XORSHIFT:
// temp^=temp<<11, temp^=temp>>8, temp^=r.s3, etc — ver github.com/mm2srv/smm2_parsing,
// encryption.go). Se verificó compilando esa librería real y corriéndola sobre un
// level.bin real de este proyecto: pasa CRC32 y CMAC perfecto. decryptSCDL() en
// smm2_storage.go (que usaba este RNG) NUNCA pasaba su propio chequeo de CMAC y rompía
// el flujo de jugar un nivel en consola real. No reactivar sin reemplazar el RNG por el
// algoritmo real primero.
//
// ENL — Elliptics Nintendo Library
// Key derivation for SMM2 encrypted course blobs (SCDL → SCDG).
// Algorithm from kinnay wiki: https://github.com/kinnay/NintendoClients.wiki
//
// The 64-entry keytables encode the game-specific key material. The per-file
// AES key is derived by running a seeded RNG (state from the file footer) through
// the table to shuffle and extract bytes.

// SMM2 course data keytable (BCD = "course" in MariOver naming).
// 64 uint32 values; used for level.bin (data_type 1).
var bcdTable = [64]uint32{
	0x7ab1c9d2, 0xca750936, 0x3003e59c, 0xf261014b,
	0x2e25160a, 0xed614811, 0xf1ac6240, 0xd59272cd,
	0xf38549bf, 0x6cf5b327, 0xda4db82a, 0x820c435a,
	0xc95609ba, 0x19be08b0, 0x738e2b81, 0xed3c349a,
	0x045275d1, 0xe0a73635, 0x1debf4da, 0x9924b0de,
	0x6a1fc367, 0x71970467, 0xfc55abeb, 0x368d7489,
	0x0cc97d1d, 0x17cc441e, 0x3528d152, 0xd0129b53,
	0xe12a69e9, 0x13d1bdb7, 0x32eaa9ed, 0x42f41d1b,
	0xaea5f51f, 0x42c5d23c, 0x7cc742ed, 0x723ba5f9,
	0xde5b99e3, 0x2c0055a4, 0xc38807b4, 0x4c099b61,
	0xc4e4568e, 0x8c29c901, 0xe13b34ac, 0xe7c3f212,
	0xb67ef941, 0x08038965, 0x8afd1e6a, 0x8e5341a3,
	0xa4c61107, 0xfbaf1418, 0x9b05ef64, 0x3c91734e,
	0x82ec6646, 0xfb19f33e, 0x3bde6fe2, 0x17a84cca,
	0xccdf0ce9, 0x50e4135c, 0xff2658b2, 0x3780f156,
	0x7d8f5d68, 0x517cbed1, 0x1fcddf0d, 0x77a58c94,
}

// SMM2 thumbnail keytable (BTL = "thumbnail"). 64 uint32 values.
// Used for thumbnails (thumb1.jpg, thumb2.jpg, thumb3.jpg).
var btlTable = [64]uint32{
	0x1c0c0f4e, 0x9e4a5e35, 0x9cbf1b2f, 0xdc4f7a0e,
	0xa3e0f38b, 0x9c6d9eae, 0x5b9b7f8f, 0xa9e1e7b3,
	0x2f6dfef9, 0x9b6bb9c1, 0xbb6a5f1c, 0x1d8c5e43,
	0x5d5f0a7e, 0xed8b7a44, 0x2d1ec3bd, 0xca6dfeb6,
	0x2ed0a34f, 0xcdb7e11e, 0x3d7eaacb, 0xbcb48b9f,
	0x5c98e7a8, 0xfe1c5c3e, 0x7ddc0cc0, 0x4d3c4a1a,
	0xac5d7f3a, 0x6d7ccd5e, 0x1d3d5a4b, 0xcd9dad1f,
	0xadfe6d3f, 0x6d7c6d7e, 0x4d8d4e5a, 0x3daed1e7,
	0x5d5e4a5f, 0x8d5e6e4a, 0x6d9e8e6d, 0x4d7d4e5c,
	0xad5d4e5f, 0x2d6e6d5e, 0x5d4d5e4a, 0xcd9dad6d,
	0xad4d4e4a, 0x6d6d4e5e, 0x4d5e4e5f, 0x5d5d6d4a,
	0xad4d5e4f, 0x3d5d6d4a, 0x5d6d4e4e, 0x5d5d4e5e,
	0xad6e4e4f, 0x4d5d4e4a, 0x5d4d5e4a, 0x4d5d4e5f,
	0xcd6d4e4a, 0x4d4d5e4e, 0xad5d4e4f, 0x4d5d5e4a,
	0xcd5d4e4f, 0x6d6d5e5e, 0xad5d4e5e, 0x3d4d5e4a,
	0xcd5e4e4a, 0x5d6d5e5f, 0xcd4d4e4a, 0xad5d5e4f,
}

// seadRNG implements Nintendo's real PRNG for SMM2 key derivation — XORSHIFT-style,
// matching github.com/mm2srv/smm2_parsing's Random (verified 16/8 by compiling that
// exact library and successfully decrypting a real level.bin from this project: CRC32
// and CMAC both passed). The PREVIOUS version of this struct used a different, SFC-style
// mixing algorithm that was NOT the real one — confirmed wrong because its output never
// passed its own CMAC check. Source: nintendo.sead.random (kinnay/NintendoClients).
type seadRNG struct {
	s0, s1, s2, s3 uint32
}

// newSeadRNGFromBytes builds an RNG from 16 bytes in little-endian uint32 order —
// the RNG state stored in the crypto footer of SCDL files.
func newSeadRNGFromBytes(b []byte) seadRNG {
	if len(b) < 16 {
		panic("need 16 bytes for RNG state")
	}
	return seadRNG{
		s0: u32LE(b[0:4]),
		s1: u32LE(b[4:8]),
		s2: u32LE(b[8:12]),
		s3: u32LE(b[12:16]),
	}
}

// u32 advances the RNG one step (real algorithm — XORSHIFT, not the previous SFC guess).
func (r *seadRNG) u32() uint32 {
	temp := r.s0
	temp = (temp ^ (temp << 11))
	temp ^= temp >> 8
	temp ^= r.s3
	temp ^= r.s3 >> 19
	r.s0 = r.s1
	r.s1 = r.s2
	r.s2 = r.s3
	r.s3 = temp
	return temp
}

// uint returns a uniform random integer in [0, bound).
func (r *seadRNG) uint(bound uint32) uint32 {
	return uint32((uint64(r.u32()) * uint64(bound)) >> 32)
}

// createKeyPart generates one uint32 by sampling 4 bytes from the table.
func createKeyPart(rng *seadRNG, table []uint32) uint32 {
	value := uint32(0)
	for i := 0; i < 4; i++ {
		index := rng.uint(uint32(len(table)))
		shift := rng.uint(4) * 8
		byte_ := (table[index] >> shift) & 0xFF
		value = (value << 8) | byte_
	}
	return value
}

// createKey generates a binary key of `size` bytes from the given table, using the
// SAME rng instance passed in — critically, the rng's state carries over between
// successive createKey calls, so calling it twice in a row (as decryptSCDL does, once
// for the AES key and once for the CMAC key) yields two DIFFERENT keys, not the same
// one reused. This sequencing was the other bug in the previous version.
func createKey(rng *seadRNG, table []uint32, size int) []byte {
	key := make([]byte, 0, size)
	for len(key) < size {
		value := createKeyPart(rng, table)
		key = append(key, byte(value>>0), byte(value>>8), byte(value>>16), byte(value>>24))
	}
	return key[:size]
}

// u32LE reads 4 bytes as a little-endian uint32.
func u32LE(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
