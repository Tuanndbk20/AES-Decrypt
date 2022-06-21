package AESDecrypt;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class AESEngineCTRmode {
	public final static int BLOCK_SIZE = (128 / 8);
	public final int KEY_SIZE = (128 / 8);
	public final static int ROUND_NO = 10;
	public static byte[] IV = new byte[BLOCK_SIZE];
	public static byte[] Ctr = new byte[BLOCK_SIZE];

//	public static byte[] plaintext;

	/* Transform a byte array in an hexadecimal string */
	private static String toHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	/* Transform a byte array in an hexadecimal string */
	private static String toHex(byte data) {
		StringBuilder sb = new StringBuilder();
		byte b = data;
		sb.append(String.format("%02x", b & 0xff));
		return sb.toString();
	}

	/* Convert long to byte array */
	private static byte[] longToByteArray(long value) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(value);
		return buffer.array();

	}

	/* Convert a string representation in its hexadecimal string */
	private static String toHex(String arg) {
		return String.format("%02x", new BigInteger(1, arg.getBytes()));
	}

	/*
	 * Transform an hexadecimal string in byte array (It works if the string only
	 * contains the hexadecimal characters)
	 */
	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	// The S box
	private static final byte[] sBox = { (byte) 99, (byte) 124, (byte) 119, (byte) 123, (byte) 242, (byte) 107,
			(byte) 111, (byte) 197, (byte) 48, (byte) 1, (byte) 103, (byte) 43, (byte) 254, (byte) 215, (byte) 171,
			(byte) 118, (byte) 202, (byte) 130, (byte) 201, (byte) 125, (byte) 250, (byte) 89, (byte) 71, (byte) 240,
			(byte) 173, (byte) 212, (byte) 162, (byte) 175, (byte) 156, (byte) 164, (byte) 114, (byte) 192, (byte) 183,
			(byte) 253, (byte) 147, (byte) 38, (byte) 54, (byte) 63, (byte) 247, (byte) 204, (byte) 52, (byte) 165,
			(byte) 229, (byte) 241, (byte) 113, (byte) 216, (byte) 49, (byte) 21, (byte) 4, (byte) 199, (byte) 35,
			(byte) 195, (byte) 24, (byte) 150, (byte) 5, (byte) 154, (byte) 7, (byte) 18, (byte) 128, (byte) 226,
			(byte) 235, (byte) 39, (byte) 178, (byte) 117, (byte) 9, (byte) 131, (byte) 44, (byte) 26, (byte) 27,
			(byte) 110, (byte) 90, (byte) 160, (byte) 82, (byte) 59, (byte) 214, (byte) 179, (byte) 41, (byte) 227,
			(byte) 47, (byte) 132, (byte) 83, (byte) 209, (byte) 0, (byte) 237, (byte) 32, (byte) 252, (byte) 177,
			(byte) 91, (byte) 106, (byte) 203, (byte) 190, (byte) 57, (byte) 74, (byte) 76, (byte) 88, (byte) 207,
			(byte) 208, (byte) 239, (byte) 170, (byte) 251, (byte) 67, (byte) 77, (byte) 51, (byte) 133, (byte) 69,
			(byte) 249, (byte) 2, (byte) 127, (byte) 80, (byte) 60, (byte) 159, (byte) 168, (byte) 81, (byte) 163,
			(byte) 64, (byte) 143, (byte) 146, (byte) 157, (byte) 56, (byte) 245, (byte) 188, (byte) 182, (byte) 218,
			(byte) 33, (byte) 16, (byte) 255, (byte) 243, (byte) 210, (byte) 205, (byte) 12, (byte) 19, (byte) 236,
			(byte) 95, (byte) 151, (byte) 68, (byte) 23, (byte) 196, (byte) 167, (byte) 126, (byte) 61, (byte) 100,
			(byte) 93, (byte) 25, (byte) 115, (byte) 96, (byte) 129, (byte) 79, (byte) 220, (byte) 34, (byte) 42,
			(byte) 144, (byte) 136, (byte) 70, (byte) 238, (byte) 184, (byte) 20, (byte) 222, (byte) 94, (byte) 11,
			(byte) 219, (byte) 224, (byte) 50, (byte) 58, (byte) 10, (byte) 73, (byte) 6, (byte) 36, (byte) 92,
			(byte) 194, (byte) 211, (byte) 172, (byte) 98, (byte) 145, (byte) 149, (byte) 228, (byte) 121, (byte) 231,
			(byte) 200, (byte) 55, (byte) 109, (byte) 141, (byte) 213, (byte) 78, (byte) 169, (byte) 108, (byte) 86,
			(byte) 244, (byte) 234, (byte) 101, (byte) 122, (byte) 174, (byte) 8, (byte) 186, (byte) 120, (byte) 37,
			(byte) 46, (byte) 28, (byte) 166, (byte) 180, (byte) 198, (byte) 232, (byte) 221, (byte) 116, (byte) 31,
			(byte) 75, (byte) 189, (byte) 139, (byte) 138, (byte) 112, (byte) 62, (byte) 181, (byte) 102, (byte) 72,
			(byte) 3, (byte) 246, (byte) 14, (byte) 97, (byte) 53, (byte) 87, (byte) 185, (byte) 134, (byte) 193,
			(byte) 29, (byte) 158, (byte) 225, (byte) 248, (byte) 152, (byte) 17, (byte) 105, (byte) 217, (byte) 142,
			(byte) 148, (byte) 155, (byte) 30, (byte) 135, (byte) 233, (byte) 206, (byte) 85, (byte) 40, (byte) 223,
			(byte) 140, (byte) 161, (byte) 137, (byte) 13, (byte) 191, (byte) 230, (byte) 66, (byte) 104, (byte) 65,
			(byte) 153, (byte) 45, (byte) 15, (byte) 176, (byte) 84, (byte) 187, (byte) 22 };

	// The inverse S-box
	private static final byte[] inverseSBox = { (byte) 82, (byte) 9, (byte) 106, (byte) 213, (byte) 48, (byte) 54,
			(byte) 165, (byte) 56, (byte) 191, (byte) 64, (byte) 163, (byte) 158, (byte) 129, (byte) 243, (byte) 215,
			(byte) 251, (byte) 124, (byte) 227, (byte) 57, (byte) 130, (byte) 155, (byte) 47, (byte) 255, (byte) 135,
			(byte) 52, (byte) 142, (byte) 67, (byte) 68, (byte) 196, (byte) 222, (byte) 233, (byte) 203, (byte) 84,
			(byte) 123, (byte) 148, (byte) 50, (byte) 166, (byte) 194, (byte) 35, (byte) 61, (byte) 238, (byte) 76,
			(byte) 149, (byte) 11, (byte) 66, (byte) 250, (byte) 195, (byte) 78, (byte) 8, (byte) 46, (byte) 161,
			(byte) 102, (byte) 40, (byte) 217, (byte) 36, (byte) 178, (byte) 118, (byte) 91, (byte) 162, (byte) 73,
			(byte) 109, (byte) 139, (byte) 209, (byte) 37, (byte) 114, (byte) 248, (byte) 246, (byte) 100, (byte) 134,
			(byte) 104, (byte) 152, (byte) 22, (byte) 212, (byte) 164, (byte) 92, (byte) 204, (byte) 93, (byte) 101,
			(byte) 182, (byte) 146, (byte) 108, (byte) 112, (byte) 72, (byte) 80, (byte) 253, (byte) 237, (byte) 185,
			(byte) 218, (byte) 94, (byte) 21, (byte) 70, (byte) 87, (byte) 167, (byte) 141, (byte) 157, (byte) 132,
			(byte) 144, (byte) 216, (byte) 171, (byte) 0, (byte) 140, (byte) 188, (byte) 211, (byte) 10, (byte) 247,
			(byte) 228, (byte) 88, (byte) 5, (byte) 184, (byte) 179, (byte) 69, (byte) 6, (byte) 208, (byte) 44,
			(byte) 30, (byte) 143, (byte) 202, (byte) 63, (byte) 15, (byte) 2, (byte) 193, (byte) 175, (byte) 189,
			(byte) 3, (byte) 1, (byte) 19, (byte) 138, (byte) 107, (byte) 58, (byte) 145, (byte) 17, (byte) 65,
			(byte) 79, (byte) 103, (byte) 220, (byte) 234, (byte) 151, (byte) 242, (byte) 207, (byte) 206, (byte) 240,
			(byte) 180, (byte) 230, (byte) 115, (byte) 150, (byte) 172, (byte) 116, (byte) 34, (byte) 231, (byte) 173,
			(byte) 53, (byte) 133, (byte) 226, (byte) 249, (byte) 55, (byte) 232, (byte) 28, (byte) 117, (byte) 223,
			(byte) 110, (byte) 71, (byte) 241, (byte) 26, (byte) 113, (byte) 29, (byte) 41, (byte) 197, (byte) 137,
			(byte) 111, (byte) 183, (byte) 98, (byte) 14, (byte) 170, (byte) 24, (byte) 190, (byte) 27, (byte) 252,
			(byte) 86, (byte) 62, (byte) 75, (byte) 198, (byte) 210, (byte) 121, (byte) 32, (byte) 154, (byte) 219,
			(byte) 192, (byte) 254, (byte) 120, (byte) 205, (byte) 90, (byte) 244, (byte) 31, (byte) 221, (byte) 168,
			(byte) 51, (byte) 136, (byte) 7, (byte) 199, (byte) 49, (byte) 177, (byte) 18, (byte) 16, (byte) 89,
			(byte) 39, (byte) 128, (byte) 236, (byte) 95, (byte) 96, (byte) 81, (byte) 127, (byte) 169, (byte) 25,
			(byte) 181, (byte) 74, (byte) 13, (byte) 45, (byte) 229, (byte) 122, (byte) 159, (byte) 147, (byte) 201,
			(byte) 156, (byte) 239, (byte) 160, (byte) 224, (byte) 59, (byte) 77, (byte) 174, (byte) 42, (byte) 245,
			(byte) 176, (byte) 200, (byte) 235, (byte) 187, (byte) 60, (byte) 131, (byte) 83, (byte) 153, (byte) 97,
			(byte) 23, (byte) 43, (byte) 4, (byte) 126, (byte) 186, (byte) 119, (byte) 214, (byte) 38, (byte) 225,
			(byte) 105, (byte) 20, (byte) 99, (byte) 85, (byte) 33, (byte) 12, (byte) 125 };

	// round coefficients
	private static byte[] roundCoefficient = { (byte) 1, (byte) 2, (byte) 4, (byte) 8, (byte) 16, (byte) 32, (byte) 64,
			(byte) 128, (byte) 27, (byte) 54 }; // Round coefficient is 10, the number of key is 11

	// keys
	private byte[] key = { (byte) 9, (byte) 21, (byte) 0, (byte) 151, (byte) 0, (byte) 18, (byte) 16, (byte) 19,
			(byte) 3, (byte) 2, (byte) 25, (byte) 2, (byte) 5, (byte) 0, (byte) 41, (byte) 128 };

	private static byte[][] subkeys = new byte[ROUND_NO + 1][]; // each subkey is 16-bytes length

	public byte[] getKey() {
		return key;
	};

	public void setKey(byte[] value) {
//		System.out.println("process Key!");
		if (value == null || value.length != KEY_SIZE) {
			System.out.println("value = null or value.length != KEY_SIZE");
			return;
		}
		key = value;
		System.arraycopy(key, 0, subkeys[0], 0, KEY_SIZE);
		for (int i = 0; i < ROUND_NO; ++i) {
			System.arraycopy(subkeys[i], 0, subkeys[i + 1], 0, KEY_SIZE);
			keyTransform(subkeys[i + 1], i);
		}
	}

	public static byte getSubkeys(int i, int j) {
		return subkeys[i][j];
	}

	public static byte[] getSubkeys(int i) {
		return subkeys[i];
	}

	// init AES and process Key
	public AESEngineCTRmode(byte[] key) {

		for (int i = 0; i < ROUND_NO + 1; ++i) {
			subkeys[i] = new byte[KEY_SIZE]; // All the necessary array size for this subkey is made at the beginning
		}
		if (key != null && key.length == KEY_SIZE) {
			setKey(key);
		} else {
			setKey(this.key);
		}
		////////////////////////////////////////// check roundkey
		////////////////////////////////////////// ///////////////////////////////////
//		for (int i = 0; i < 11; i++) {
//			System.out.println("\nround key " + i);
//			System.out.print(toHex(getSubkeys(i)));
//		}
	}

	// shiftrow(1 row) then subword then xor RCON => t
	private void keywordTransform(byte[] keyword, int roundno) { // round no starts from 0, ends at 9
		if (roundno < 0 || roundno > ROUND_NO - 1)
			return;
		byte buf = keyword[0];
		keyword[0] = (byte) (sBox[keyword[1] & 0xff] ^ roundCoefficient[roundno]);
		keyword[1] = sBox[keyword[2] & 0xff];
		keyword[2] = sBox[keyword[3] & 0xff];
		keyword[3] = sBox[buf & 0xff];
	}

	private void keyTransform(byte[] key, int roundno) {
		byte[] keyword = new byte[4]; // keyword = ti
		System.arraycopy(key, 12, keyword, 0, 4);
		keywordTransform(keyword, roundno);
		for (int k = 0; k < 4; ++k)
			key[k] ^= keyword[k];
		for (int i = 0; i < KEY_SIZE - 4; ++i)
			key[i + 4] ^= key[i];
	}

	private static void shiftRows(byte[] text) {
		byte buf;
		// shift row 2 (1 -> 13, 5 -> 1, 9 -> 5, 13 -> 9)
		buf = text[1];
		text[1] = text[5];
		text[5] = text[9];
		text[9] = text[13];
		text[13] = buf;

		// shift row 3 (2 -> 10, 6 -> 14, 10 -> 2, 14 -> 6)
		buf = text[2];
		text[2] = text[10];
		text[10] = buf;
		buf = text[6];
		text[6] = text[14];
		text[14] = buf;

		// shift row 4 (3 -> 7, 7 -> 11, 11 -> 15, 15 -> 3)
		buf = text[15];
		text[15] = text[11];
		text[11] = text[7];
		text[7] = text[3];
		text[3] = buf;
	}

	private static void inverseShiftRows(byte[] text) {
		byte buf;
		// inverse shift row 2 (1 -> 5, 5 -> 9, 9 -> 13, 13 -> 1)
		buf = text[1];
		text[1] = text[13];
		text[13] = text[9];
		text[9] = text[5];
		text[5] = buf;

		// inverse shift row 3 (2 -> 10, 6 -> 14, 10 -> 2, 14 -> 6)
		buf = text[2];
		text[2] = text[10];
		text[10] = buf;
		buf = text[6];
		text[6] = text[14];
		text[14] = buf;

		// inverse shift row 4 (3 -> 15, 7 -> 3, 11 -> 7, 15 -> 11)
		buf = text[15];
		text[15] = text[3];
		text[3] = text[7];
		text[7] = text[11];
		text[11] = buf;
	}

	public final static byte BYTE_POLY_REDUCTION = 0x1b; // 0x1b

	private static byte galoisMult2(byte val) { // used for GaloisMult with 2 equal shift left 1 bit and xor with
												// condition
		byte polyRed = BYTE_POLY_REDUCTION;
		return ((val & 0xff) >= 128) ? (byte) ((val << 1) ^ (polyRed)) : (byte) (val << 1); // compare with 128 to check
																							// MSB of value =1?
//		return (val >= (byte) 128 ? (byte) ((val << 1) ^ (polyRed)) : (byte) (val << 1));
	}

	private static byte[] quickXORTable = { (byte) 0, (byte) 27, (byte) 54, (byte) 45, (byte) 108, (byte) 119,
			(byte) 90, (byte) 65 };

	private static byte galoisDefaultMult(byte val, byte mult) {
		int buf = ((val & 0xff) << 3);
		if (mult != 0x0E)
			buf ^= (val & 0xff);
		if (mult > 0x0C)
			buf ^= ((val & 0xff) << 2);
		if ((mult & 0x02) > 0)
			buf ^= ((val & 0xff) << 1);
		byte xorval = quickXORTable[(buf >> 8) & 0x07];
		return ((xorval & 0xff) == 0) ? (byte) buf : (byte) (buf ^ xorval);
	}

	private static void mixColumn(byte[] text) {
		byte[] temp = new byte[4];
		int p;
		for (int i = 0; i < 4; ++i) {
			p = i * 4;
			temp[0] = (byte) (galoisMult2(text[p]) ^ (galoisMult2(text[p + 1]) ^ text[p + 1]) ^ text[p + 2]
					^ text[p + 3]);
			temp[1] = (byte) (text[p] ^ galoisMult2(text[p + 1]) ^ (galoisMult2(text[p + 2]) ^ text[p + 2])
					^ text[p + 3]);
			temp[2] = (byte) (text[p] ^ text[p + 1] ^ galoisMult2(text[p + 2])
					^ (galoisMult2(text[p + 3]) ^ text[p + 3]));
			temp[3] = (byte) ((galoisMult2(text[p]) ^ text[p]) ^ text[p + 1] ^ text[p + 2] ^ galoisMult2(text[p + 3]));
			System.arraycopy(temp, 0, text, p, 4);
//			System.out.println(p + " temp: " + toHex(temp));
		}
	}

	private static byte[] inverseMixColumnMatrixElementTable = { (byte) 11, (byte) 13, (byte) 9, (byte) 14, (byte) 11,
			(byte) 13, (byte) 9 };

	private static void inverseMixColumn(byte[] text) {
		byte[] temp = new byte[4];
		int p, p2;
		for (int i = 0; i < 4; ++i) {
			p = i * 4;
			for (int j = 0; j < 4; ++j) {
				p2 = 3 - j;
				temp[j] = (byte) (galoisDefaultMult(text[p], inverseMixColumnMatrixElementTable[p2])
						^ galoisDefaultMult(text[p + 1], inverseMixColumnMatrixElementTable[p2 + 1])
						^ galoisDefaultMult(text[p + 2], inverseMixColumnMatrixElementTable[p2 + 2])
						^ galoisDefaultMult(text[p + 3], inverseMixColumnMatrixElementTable[p2 + 3]));
			}
			System.arraycopy(temp, 0, text, p, 4);
		}
	}

	/********************************
	 * same below but print functions shift, add, mix, subbyte
	 *******************************/
//	public void encryptBlock(byte[] plaintext, byte[] ciphertext) { // since this is private function, no "input
//																	// protection" is needed.
//		System.arraycopy(plaintext, 0, ciphertext, 0, plaintext.length);
//		System.out.println("plaintext in block: " + toHex(plaintext));
//
//		for (int j = 0; j < BLOCK_SIZE; ++j)
//			ciphertext[j] ^= getSubkeys(0, j); // addRoundKey for preround 1
//
//		System.out.println("addroundkey preround 1: " + toHex(ciphertext) + "\n");
//		// process rounds
//		for (int r = 0; r < ROUND_NO; ++r) {
//			for (int i = 0; i < BLOCK_SIZE; ++i) {
//				ciphertext[i] = sBox[ciphertext[i] & 0xff]; // subytes
//			}
//			System.out.println("after Sbox " + (r + 1) + ": " + toHex(ciphertext));
//
//			shiftRows(ciphertext);
//			System.out.println("after shiftRows " + (r + 1) + ": " + toHex(ciphertext));
//
//			if (r < ROUND_NO - 1) {
//				mixColumn(ciphertext);
//				System.out.println("after mixColumn " + (r + 1) + ": " + toHex(ciphertext));
//			}
//
//			for (int j1 = 0; j1 < BLOCK_SIZE; ++j1)
//				ciphertext[j1] ^= getSubkeys(r + 1, j1);
//			System.out.println("after addRoundKey round " + (r + 1) + ": " + toHex(ciphertext) + "\n");
//		}
//
//	}
//
//	private static void decryptBlock(byte[] ciphertext, byte[] plaintext) { // since this is private function, no "input
//																			// protection" is needed.
//		System.arraycopy(ciphertext, 0, plaintext, 0, plaintext.length);
//		// addRoundkey
//		for (int j = 0; j < BLOCK_SIZE; ++j)
//			plaintext[j] ^= getSubkeys(ROUND_NO, j);
//		System.out.println("Roundkey 10 :" + toHex(getSubkeys(ROUND_NO)));
//		System.out.println("\nafter AddRoundkey: " + toHex(plaintext));
//
//		for (int r = 0; r < ROUND_NO; ++r) {
//			inverseShiftRows(plaintext);
//			System.out.println("after inverseShiftRows Round " + (r + 1) + ": " + toHex(plaintext));
//
//			for (int i = 0; i < BLOCK_SIZE; ++i)
//				plaintext[i] = inverseSBox[plaintext[i] & 0xff];
//			System.out.println("after inverseSBox Round " + (r + 1) + ": " + toHex(plaintext));
//
//			for (int j = 0; j < BLOCK_SIZE; ++j)
//				plaintext[j] ^= getSubkeys(ROUND_NO - r - 1, j);
//			System.out.println("key round " + (ROUND_NO - r - 1) + ": " + toHex(getSubkeys(ROUND_NO - r - 1)));
//			System.out.println("after AddRoundkey Round " + (r + 1) + ": " + toHex(plaintext));
//
//			if (r < 9) {
//				inverseMixColumn(plaintext);
//				System.out.println("after inverseMixColumn Round " + (r + 1) + ": " + toHex(plaintext) + "\n");
//			}
//		}
//	}

	public static void encryptBlock(byte[] plaintext, byte[] ciphertext) { // since this is private function, no "input
		// protection" is needed.
		System.arraycopy(plaintext, 0, ciphertext, 0, plaintext.length);

		for (int j = 0; j < BLOCK_SIZE; ++j)
			ciphertext[j] ^= getSubkeys(0, j); // addRoundKey for preround 1

		// process rounds
		for (int r = 0; r < ROUND_NO; ++r) {
			for (int i = 0; i < BLOCK_SIZE; ++i) {
				ciphertext[i] = sBox[ciphertext[i] & 0xff]; // subytes
			}

			shiftRows(ciphertext);

			if (r < ROUND_NO - 1) {
				mixColumn(ciphertext);
			}

			for (int j1 = 0; j1 < BLOCK_SIZE; ++j1)
				ciphertext[j1] ^= getSubkeys(r + 1, j1);
		}

	}

	private static void decryptBlock(byte[] ciphertext, byte[] plaintext) { // since this is private function, no "input
		// protection" is needed.
		System.arraycopy(ciphertext, 0, plaintext, 0, plaintext.length);
// addRoundkey
		for (int j = 0; j < BLOCK_SIZE; ++j)
			plaintext[j] ^= getSubkeys(ROUND_NO, j);

		for (int r = 0; r < ROUND_NO; ++r) {
			inverseShiftRows(plaintext);

			for (int i = 0; i < BLOCK_SIZE; ++i)
				plaintext[i] = inverseSBox[plaintext[i] & 0xff];

			for (int j = 0; j < BLOCK_SIZE; ++j)
				plaintext[j] ^= getSubkeys(ROUND_NO - r - 1, j);

			if (r < 9) {
				inverseMixColumn(plaintext);
			}
		}
	}


	/************************************* ECB mode ******************************/
//	public boolean Encrypt(byte[] plaintext, byte[] ciphertext) {
//		if (plaintext == null || ciphertext == null || ciphertext.length < plaintext.length) // invalid input(s)
//			return false;
//		int extrabytes = plaintext.length % BLOCK_SIZE;
//		int pblock = plaintext.length / BLOCK_SIZE;
//		byte[] text = new byte[BLOCK_SIZE];
//		int p;
//
//		for (int k = 0; k < pblock; ++k) { // Encrypt all possible blocks
//			p = k * BLOCK_SIZE;
//			System.arraycopy(plaintext, p, text, 0, BLOCK_SIZE);
//			encryptBlock(text, text);
//			System.arraycopy(text, 0, ciphertext, p, BLOCK_SIZE);
//		}
//
//		if (extrabytes > 0) { // encrypt the left over
//			p = pblock * BLOCK_SIZE;
//			System.arraycopy(plaintext, p, text, 0, extrabytes);
//			for (int i = extrabytes; i < BLOCK_SIZE; ++i) { // TODO not sure if there is any faster way in C#
//				text[i] = 0;
//				if (i == BLOCK_SIZE - 1) {
//					text[i] = (byte) extrabytes;
//				}
//			}
//			encryptBlock(text, text);
//			System.arraycopy(text, 0, ciphertext, p, BLOCK_SIZE);
//		}
//		return true;
//	}
//
//	public static byte[] Decrypt(byte[] ciphertext) { // can only recover up to valid multiplication
//		byte[] plaintext = new byte[ciphertext.length];	
//		int cblock = (ciphertext.length / BLOCK_SIZE);
//		
//		byte[] text = new byte[BLOCK_SIZE];
//		int p;
//		for (int k = 0; k < cblock-1; ++k) {
//			p = k * BLOCK_SIZE;
//			System.arraycopy(ciphertext, p, text, 0, BLOCK_SIZE);
//			decryptBlock(text, text);
//			System.arraycopy(text, 0, plaintext, p, BLOCK_SIZE);
//		} // extra bytes are not taken cared of...
//		
//		// cut byte of plaintext residuals
//		System.arraycopy(ciphertext, (cblock-1)*BLOCK_SIZE, text, 0, BLOCK_SIZE);
//		decryptBlock(text, text);
//		
//		int num=Integer.parseInt(toHex(text[BLOCK_SIZE-1]), 16) ;
//		System.arraycopy(text, 0, plaintext, (cblock-1)*BLOCK_SIZE, num);
//
//		byte[] result = new byte[plaintext.length-BLOCK_SIZE+num];
//		System.arraycopy(plaintext, 0, result, 0, result.length);
//		return result;
//	}
	
	
	
	

	/**************************** CBC mode *******************************/
//	public static void initIV(byte[] iv) {
//		for (int i = 0; i < BLOCK_SIZE; i++) {
//			iv[i] = 0;
//			if (i == 15)
//				iv[i] = 1;
//		}
//	}
//
//	public boolean Encrypt(byte[] plaintext, byte[] ciphertext) {
//		if (plaintext == null || ciphertext == null || ciphertext.length < plaintext.length) // invalid input(s)
//			return false;
//		int extrabytes = plaintext.length % BLOCK_SIZE;
//		int pblock = plaintext.length / BLOCK_SIZE;
//		byte[] text = new byte[BLOCK_SIZE];
//		int p;
//
//		System.arraycopy(plaintext, 0, text, 0, BLOCK_SIZE);
//		for (int k = 0; k < pblock; ++k) { // Encrypt all possible blocks
//			p = k * BLOCK_SIZE;
//			// process P1 with IV
//			if (k == 0) {
//				// init IV
//				initIV(IV);
//				for (int i = 0; i < BLOCK_SIZE; i++) {
//					text[i] ^= IV[i];
//				}
////				System.out.println(k+" text after xor: "+toHex(text));
//			} else {
//				// process Pi with Ci
////				System.out.println(k+" text "+toHex(text));
//				if ((p + BLOCK_SIZE) <= plaintext.length) {
//					for (int i = 0; i < BLOCK_SIZE; i++) {
//						text[i] ^= plaintext[p + i];
//					}
////					System.out.println(k+" text after xor: "+toHex(text));
//				}
//			}
//			encryptBlock(text, text);
////			System.out.println(k+" text after encrypt: "+toHex(text));
//			System.arraycopy(text, 0, ciphertext, p, BLOCK_SIZE);
//		}
//
//		if (extrabytes > 0) { // encrypt the left over
//			p = pblock * BLOCK_SIZE;
//			byte[] temp = new byte[BLOCK_SIZE];
//			System.arraycopy(plaintext, p, temp, 0, extrabytes);
//			for (int i = extrabytes; i < BLOCK_SIZE; ++i) { // TODO not sure if there is any faster way in C#
//				temp[i] = (byte)0;
//				if (i == BLOCK_SIZE - 1) {
//					temp[i] = (byte) extrabytes;
//				}
//			}
//			for (int i = 0; i < BLOCK_SIZE; i++) {
//				text[i] ^= temp[i];
//			}
//			encryptBlock(text, text);
//			System.arraycopy(text, 0, ciphertext, p, BLOCK_SIZE);
//		}
//		return true;
//	}
//
//	public static byte[] Decrypt(byte[] ciphertext) { // can only recover up to valid multiplication
//		byte[] plaintext = new byte[ciphertext.length];
//		int cblock = (ciphertext.length / BLOCK_SIZE);
//
//		byte[] text = new byte[BLOCK_SIZE];
//		int p;
//				
//		initIV(IV);
//		for (int k = 0; k < cblock; ++k) {
//			p = k * BLOCK_SIZE;
//			System.arraycopy(ciphertext, p, text, 0, BLOCK_SIZE);
//			decryptBlock(text, text);
//			if (k == 0) {
//				for (int i = 0; i < BLOCK_SIZE; i++) {
//					text[i] ^= IV[i];
//				}
//			} else {
//				for (int i = 0; i < BLOCK_SIZE; i++) {
//					text[i] ^= ciphertext[p + i - BLOCK_SIZE];
//				}
//			}
//			System.arraycopy(text, 0, plaintext, p, BLOCK_SIZE);
//		} // extra bytes are not taken cared of...
//
//
//		int num = Integer.parseInt(toHex(text[BLOCK_SIZE - 1]), 16);
//		System.arraycopy(text, 0, plaintext, (cblock - 1) * BLOCK_SIZE, num);
//		
//		byte[] result = new byte[plaintext.length - BLOCK_SIZE + num];
//		System.arraycopy(plaintext, 0, result, 0, result.length);
//		return result;
//	}

	/********************************** CTR mode *******************************/
	public static void initCTR(byte[] ctr) {
		for (int i = 0; i < BLOCK_SIZE; i++) {
			ctr[i] = 0;
//			if(i==15) {
//				ctr[i]=1;
//			}
		}
	}

	public static void increCTR(byte[] ctr) {
		int mem = 1;
		for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
			ctr[i] ^= mem;
			if (i != 0 && ctr[i] == 0 && mem == 1) {
				mem = 1;
			} else {
				if (i == 0 && ctr[i] == 0 && mem == 1) {
					System.out.println("overbuffer!");
					break;
				}
				mem = 0;
			}
		}
		;
	}

	public boolean Encrypt(byte[] plaintext, byte[] ciphertext) {
		if (plaintext == null || ciphertext == null || ciphertext.length < plaintext.length) // invalid input(s)
			return false;
		int extrabytes = plaintext.length % BLOCK_SIZE;
		int pblock = plaintext.length / BLOCK_SIZE;
		byte[] text = new byte[BLOCK_SIZE];
		int p;

		initCTR(Ctr);
		for (int k = 0; k < pblock; ++k) { // Encrypt all possible blocks
			p = k * BLOCK_SIZE;
			encryptBlock(Ctr, text);

			for (int i = 0; i < BLOCK_SIZE; i++) {
				text[i] ^= plaintext[p + i];
			}
			increCTR(Ctr);
			System.arraycopy(text, 0, ciphertext, p, BLOCK_SIZE);
		}

		if (extrabytes > 0) { // encrypt the left over
			byte[] temp = new byte[BLOCK_SIZE];
			p = pblock * BLOCK_SIZE;
			encryptBlock(Ctr, text);

//			System.out.println(" Ctr after encrypt: "+toHex(text));
			System.arraycopy(plaintext, p, temp, 0, extrabytes);
			for (int i = extrabytes; i < BLOCK_SIZE; ++i) { // TODO not sure if there is any faster way in C#
				temp[i] = 0;
				if (i == BLOCK_SIZE - 1) {
					temp[i] = (byte) extrabytes;
				}
			}

			for (int i = 0; i < BLOCK_SIZE; i++) {
				text[i] ^= temp[i];
			}
			
//			System.out.println("Pk after xor: "+toHex(text));
			System.arraycopy(text, 0, ciphertext, p, BLOCK_SIZE);		}
		return true;
	}

	public static byte[] Decrypt(byte[] ciphertext) { // can only recover up to valid multiplication // of 16, extra
														// bytes are not decrypted
		byte[] plaintext = new byte[ciphertext.length];
		int cblock = (ciphertext.length / BLOCK_SIZE);

		byte[] text = new byte[BLOCK_SIZE];
		int p;

		initCTR(Ctr);
//		System.out.println("intialize ctr: "+toHex(Ctr));
		for (int k = 0; k < cblock; ++k) {
			p = k * BLOCK_SIZE;
			encryptBlock(Ctr, text);
			for (int i = 0; i < BLOCK_SIZE; i++) {
				text[i] ^= ciphertext[p + i];
			}
			increCTR(Ctr);
			System.arraycopy(text, 0, plaintext, p, BLOCK_SIZE);
		} // extra bytes are not taken cared of...
		
		// cut byte of plaintext residuals
		int num = Integer.parseInt(toHex(text[BLOCK_SIZE - 1]), 16);
		System.arraycopy(text, 0, plaintext, (cblock - 1) * BLOCK_SIZE, num);

		byte[] result = new byte[plaintext.length - BLOCK_SIZE + num];
		System.arraycopy(plaintext, 0, result, 0, result.length);
		return result;
	}

}