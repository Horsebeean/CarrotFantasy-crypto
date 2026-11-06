# CarrotFantasy-crypto
decrypt .pvr.ccz files in the game Carrot Fantasy 2, 3 and Go.  
解密保卫萝卜2、3和阿波之旅的.pvr.ccz纹理文件，3代和阿波之旅也是相同的解密算法，但使用了不同的密钥表。
解密保卫萝卜3、4和阿波之旅的czzf加密文件。
强行通过保卫萝卜3单机版和4的签名校验（已完成），过反调试检测（还没有）。

## 用法
```bash
python pvrccz_crypto.py [-h] [--decrypt] [--encrypt] [--batch] [--key KEYFILEPATH]
```

## 示例
```bash
python pvrccz_crypto.py ./test/TBuff.pvr.ccz ./test/TBuff_d.pvr.ccz --decrypt --key ./decryption_key_carrot3.bin
```
