from functools import wraps
import struct
import zlib
import os
import argparse

DEBUG = False
def logDebug(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)

KEY_COUNT = 1024
def loadKeyTable(keyFilePath):
    global key_table
    with open(keyFilePath, "rb") as f:
        key_table_buf = f.read()
        assert len(key_table_buf) == KEY_COUNT * 4
        key_table = struct.unpack('<'+'I'*KEY_COUNT, key_table_buf)


def xorCrypt(buf: bytes) -> bytes:
    if len(buf) % 4 == 0: # python切片如果为0直接返回全部了，所以要额外判断
        tail = b''
    else:
        tail = buf[-(len(buf) % 4):]
    dword_count = len(buf) // 4
    i = 0
    key_idx = 0
    # print(f"{dword_count*4=}, {len(buf)=}")
    result = list(struct.unpack('<'+'I'*dword_count, buf[:dword_count*4]))
    # 1.逐个处理，最多 512 个 DWORD
    while i < dword_count and i < 512:
        result[i] ^= key_table[key_idx]
        key_idx = (key_idx + 1) % KEY_COUNT
        i += 1
    # 2.每次跳 4 个 DWORD
    while i < dword_count and i < dword_count - 512:
        result[i] ^= key_table[key_idx]
        key_idx = (key_idx + 1) % KEY_COUNT
        i += 4
    # 3.处理剩余
    while i < dword_count:
        result[i] ^= key_table[key_idx]
        key_idx = (key_idx + 1) % KEY_COUNT
        i += 1

    result_buf = struct.pack('<'+'I'*dword_count, *result) + tail
    return result_buf

def decryptAndDecompressFile(inputFilePath, outputFilePath) -> bool:
    if not os.path.isfile(inputFilePath):
        print(f'skipped {inputFilePath}: not a file')
        return False
    with open(inputFilePath, "rb") as f:
        file_buf = f.read()

    # if file_buf[:4] != b'czzf':
    #     print(f"skipped {inputFilePath}: czzf magic mismatch.")
    #     return False
    
    expected_crc32, _, expected_length = struct.unpack("<III", file_buf[8:20])
    encrypted = file_buf[20:]
    decrypted = xorCrypt(encrypted)
    decompressed = zlib.decompress(decrypted)
    practical_crc32 = zlib.crc32(decompressed)
    practical_length = len(decompressed)
    if expected_crc32 != practical_crc32:
        print(f"CRC32 mismatch: expected {expected_crc32}, practical {practical_crc32} ({inputFilePath} -> {outputFilePath})")
    if expected_length != practical_length:
        print(f"length mismatch: expected {expected_length}, practical {practical_length} ({inputFilePath} -> {outputFilePath})")
    with open(outputFilePath, "wb") as f:
        f.write(decompressed)
    return True

def encryptAndCompressFile(inputFilePath, outputFilePath) -> bool:
    if not os.path.isfile(inputFilePath):
        print(f'skipped {inputFilePath}: not a file')
        return False
    with open(inputFilePath, "rb") as f:
        file_buf = f.read()

    input_crc32 = zlib.crc32(file_buf)
    input_length = len(file_buf)
    compressed = zlib.compress(file_buf, level=6)
    encrypted = xorCrypt(compressed)

    result_buf = b'czzfe\0\0\0'
    result_buf += struct.pack("<III", input_crc32, 0, input_length)
    result_buf += encrypted
    logDebug(f"CRC32: {input_crc32}")
    logDebug(f"length: {input_length} -> {len(result_buf)}")
    with open(outputFilePath, "wb") as f:
        f.write(result_buf)
    return True



def decoratorToBatch(func):
    """
    原函数签名: func(inputFilePath, outputFilePath) -> bool
    转换后签名: func(inputDir, outputDir)
    """
    @wraps(func)
    def result(inputDir, outputDir):
        os.makedirs(outputDir, exist_ok=True)
        successes = 0
        counter = 0
        for root, dirs, files in os.walk(inputDir):
            for filename in files:
                input_path = os.path.join(root, filename)
                # 计算相对路径，保持目录结构
                rel_path = os.path.relpath(input_path, inputDir)
                output_path = os.path.join(outputDir, rel_path)
                logDebug(f'{input_path=} {output_path=} {rel_path=}')
                # 确保输出文件的父目录存在
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                # 调用原有函数
                counter += 1
                try:
                    if func(input_path, output_path):
                        successes += 1
                except Exception as e:
                    print(f'`{e}` occurs when handing {input_path}')
        print(f'batch execution is complete ({successes}/{counter} successes)')
    return result

def main():
    arg_parser = argparse.ArgumentParser(description="czzfe file cryption of Carrot Fantasy 3 and Carrot Fantasy Go")
    arg_parser.add_argument("inputFilePath", type=str, help="Input filepath")
    arg_parser.add_argument("outputFilePath", type=str, help="Output filepath")
    arg_parser.add_argument("--decrypt", dest="method", action='store_const', const=decryptAndDecompressFile, default=decryptAndDecompressFile)
    arg_parser.add_argument("--encrypt", dest="method", action='store_const', const=encryptAndCompressFile, default=decryptAndDecompressFile)
    arg_parser.add_argument("--debug", dest="debug", action='store_true')
    arg_parser.add_argument("--batch", dest="batch", action='store_true')
    arg_parser.add_argument("--key", dest="keyFilePath", help="Specifies the key table file used for cryption.")
    args = arg_parser.parse_args()

    DEBUG = args.debug

    if args.batch:
        args.method = decoratorToBatch(args.method)

    if args.keyFilePath != None:
        loadKeyTable(args.keyFilePath)
    else:
        loadKeyTable(os.path.dirname(__file__)+"/czzfe_keys.bin")

    # print(args)
    args.method(args.inputFilePath, args.outputFilePath)



if __name__ == "__main__":
    main()