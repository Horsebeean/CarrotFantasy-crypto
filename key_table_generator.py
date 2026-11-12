import struct
import argparse

DEBUG = False
def logDebug(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)

# generate key table of czzfe crypto.

ROUNDS = 6 # 6 in carrot1,2,3,4(CCZp); 8 only in carrot4 FFDBFFEE crypto

def generateKeyTable(initKey : bytes | bytearray) -> bytes:
    assert len(initKey) == 16
    init_key_dwords = struct.unpack("<4I", initKey)
    result_length = 1024
    result = [0] * result_length
    v2 = result[result_length - 1]
    v3 = result[0]
    v4 = 0
    for i in range(ROUNDS): 
        v4 = (v4 - 1640531527) & 0xFFFFFFFF # uint32 mask for python
        v6 = 0
        v7 = (v4 >> 2) & 3
        v7 &= 0xFFFFFFFF
        while v6 != result_length - 1:
            v8 = v6
            v9 = init_key_dwords[(v6 & 3) ^ v7]
            v6 += 1
            v2 = ((((4 * result[v6]) ^ (v2 >> 5)) + ((result[v6] >> 3) ^ (16 * v2))) ^ ((v9 ^ v2) + (result[v6] ^ v4))) + v3
            v2 &= 0XFFFFFFFF
            v3 = result[v6]
            result[v8] = v2
        v3 = result[0]
        v2 = ((((4 * v3) ^ (v2 >> 5)) + ((v3 >> 3) ^ (16 * v2))) ^ ((init_key_dwords[v7 ^ 3] ^ v2) + (v3 ^ v4))) + result[result_length - 1]
        v2 &= 0XFFFFFFFF
        result[result_length - 1] = v2

    return struct.pack(f"<{result_length}I", *result)


def main():
    arg_parser = argparse.ArgumentParser(description="Key Table Generator for Carrot 2,3,go,4")
    arg_parser.add_argument("outputFilePath", type=str, help="Output filepath")
    arg_parser.add_argument("--debug", dest="debug", action='store_true')
    arg_parser.add_argument("--rounds", type=int, default=6)
    arg_parser.add_argument("--key", type=str, help="Specifies the key table file used for cryption.")
    args = arg_parser.parse_args()
    # carrot1 .pvr.ccz CCZp init key is set by a function which is called by a function calling v34 = sub_3475A0("http://clientcdn.cairot.com/android/jumpic/cd_CN.jpg")
    # sub_3A4550(0x89427C80LL, 0xF850A6D9, 0x14FB3BA0, 0x3A557437)
    # init_key = bytes.fromhex("807C4289D9A650F8A03BFB143774553A") # carrot1 CZZp
    # carrot2 .pvr.ccz CCZp init key is set by a function which is called by a function calling logger_onEvent("game_data_clear", "@last")
    # CCFileUtilsAndroid::setPVRCCZInitKey(0x67AA748A, 0xFB868651, 0xE8243360, 0x34062D80);
    # init_key = bytes.fromhex("8A74AA67518686FB603324E8802D0634") # carrot2 CZZp
    
    # carrot3 .pvr.ccz CCZp init key is set by a function which is called by a function with literal string "not Support Display resolution ratio : %.2f - %.2f"
    # v17 = CCFileUtilsAndroid::setPVRCCZInitKey(0xA8AC7F50LL, 0x63F379E7, 0x6AE82BA, 0x5405FE14);
    # init_key = bytes.fromhex("507FACA8E779F363BA82AE0614FE0554") # carrot3 CZZp

    # init_key = bytes.fromhex("5913AB26A385241C9146B3F2F62A17AA") # carrot3 czzfe

    # carrot 3 and go share the same key table.    

    # carrot4 .pvr.ccz CCZp init key is set by a function which is called by a function with encrypted string id 118, 119
    # CCFileUtilsAndroid::setPVRCCZKeys(0x3CE64A05, 0x81E437A2, 0x37DB91EC, 0x65FA03B8);
    
    # init_key = bytes.fromhex("054AE63CA237E481EC91DB37B803FA65") # carrot4 CZZp

    # init_key = bytes.fromhex("681BF24310360F9A1253C63AA36A92B8") # carrot4 0xFFDBFFEE

    DEBUG = args.debug
    ROUNDS = args.rounds
   
    result_buf = generateKeyTable(bytes.fromhex(args.key))
    with open(args.outputFilePath, "wb") as f:
        f.write(result_buf)


if __name__ == "__main__":
    main()