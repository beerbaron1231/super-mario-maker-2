package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/cmac"
	"encoding/hex"
	"fmt"
	"os"
)

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

type seadRNG struct{ s0, s1, s2, s3 uint32 }

func u32LE(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func newSeadRNG(b []byte) seadRNG {
	return seadRNG{
		s0: u32LE(b[0:4]),
		s1: u32LE(b[4:8]),
		s2: u32LE(b[8:12]),
		s3: u32LE(b[12:16]),
	}
}

func (r *seadRNG) uint(bound uint32) uint32 {
	x, y, z, w := r.s0, r.s2, r.s1, r.s3
	r.s0 = y ^ w ^ z
	r.s1 = y + z
	r.s2 = z + w
	r.s3 = x + w
	x = r.s0
	y = r.s1
	z = r.s2
	w = r.s3
	w = w ^ (w << 23)
	w = w ^ (w >> 17)
	w = w ^ (w >> 26)
	w = w ^ (w << 21)
	z = z + w
	y = z
	z = z ^ (z >> 25)
	y = y ^ (y << 23)
	z = z ^ (y >> 20)
	y = y ^ (y >> 25)
	return uint32((uint64(z) * uint64(bound)) >> 32)
}

func createKeyPart(rng *seadRNG, table []uint32) uint32 {
	v := uint32(0)
	for i := 0; i < 4; i++ {
		idx := rng.uint(64)
		shift := rng.uint(4) * 8
		b := (table[idx] >> shift) & 0xFF
		v = (v << 8) | b
	}
	return v
}

func createKey(rng *seadRNG, table []uint32, size int) []byte {
	key := make([]byte, 0, size)
	for len(key) < size {
		v := createKeyPart(rng, table)
		key = append(key, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}
	return key[:size]
}

func aesCMACStd(key, msg []byte) []byte {
	mac, _ := cmac.Sum(key, msg)
	return mac
}

func main() {
	b, err := os.ReadFile("data/courses/1003/level.bin")
	if err != nil {
		fmt.Printf("Read error: %v\n", err)
		return
	}
	fmt.Printf("File size: %d\n", len(b))

	// Check magic
	fmt.Printf("Bytes 12-15: %q\n", string(b[12:16]))

	iv := b[len(b)-48 : len(b)-32]
	rngState := b[len(b)-32 : len(b)-16]
	cmacStored := b[len(b)-16:]

	fmt.Printf("IV (hex): %s\n", hex.EncodeToString(iv))
	fmt.Printf("RNG state (hex): %s\n", hex.EncodeToString(rngState))
	fmt.Printf("CMAC stored (hex): %s\n", hex.EncodeToString(cmacStored))

	// Derive key
	rng := newSeadRNG(rngState)
	key := createKey(&rng, bcdTable[:], 16)
	fmt.Printf("Derived key: %s\n", hex.EncodeToString(key))

	// Decrypt
	ciphertext := b[16 : len(b)-48]
	fmt.Printf("Ciphertext size: %d (aligned: %v)\n", len(ciphertext), len(ciphertext)%16==0)

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("AES error: %v\n", err)
		return
	}
	plaintext := make([]byte, len(ciphertext))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plaintext, ciphertext)

	// Check decrypted magic
	fmt.Printf("Decrypted bytes 0-4: %q\n", string(plaintext[0:4]))
	fmt.Printf("Decrypted bytes 0-16 (hex): %s\n", hex.EncodeToString(plaintext[0:16]))

	// CMAC verify
	mac := aesCMACStd(key, ciphertext)
	fmt.Printf("CMAC computed: %s\n", hex.EncodeToString(mac))
	fmt.Printf("CMAC match: %v\n", string(mac) == string(cmacStored))

	// Write decrypted output
	out := make([]byte, 16+len(plaintext))
	copy(out[:], b[:16])
	out[12] = 'G'
	copy(out[16:], plaintext)
	os.WriteFile("_decrypted_level.bin", out, 0644)
	fmt.Printf("Wrote _decrypted_level.bin (%d bytes)\n", len(out))
}
