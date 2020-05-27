package ru.itis.mary230.infosec.mode;

import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.logging.Logger;

@NoArgsConstructor
public class OFBCipherMode {

    private Logger log = Logger.getLogger("OFB Encryption Mode");

    public byte[] encryptWithMode(byte[] in, Function<byte[], byte[]> encrypt, byte[] initVectorC0) {
        log.info(Arrays.toString(initVectorC0) + " INIT VECTOR");

        var blocks = getBlocks(in);
        byte[] result = new byte[blocks.size() * 16];

        byte[] prevC = initVectorC0;

        int count = 0;

        for (byte[] block : blocks) {
            prevC = encrypt.apply(prevC);
            byte[] prevBlock = arrayXor(prevC, block);
            int j = 0;
            for (int i = count * 16; i < (count + 1) * 16; i ++) {
                result[i] = prevBlock[j];
                j ++;
            }
            count ++;
        }

        return result;

    }

    public byte[] decryptWithMode(byte[] in, Function<byte[], byte[]> encrypt, byte[] initVectorC0) {

        log.info(Arrays.toString(initVectorC0) + " INIT VECTOR");

        var blocks = getBlocks(in);
        byte[] result = new byte[blocks.size() * 16];

        byte[] prevC = initVectorC0;

        int count = 0;

        for (byte[] block : blocks) {
            prevC = arrayXor(encrypt.apply(prevC), block);
            int j = 0;
            for (int i = count * 16; i < (count + 1) * 16; i ++) {
                result[i] = prevC[j];
                j ++;
            }
            count ++;
        }

        return deletePadding(result);

    }

    private byte[] arrayXor(byte[] c, byte[] p) {
        byte[] res = new byte[16];
        int i = 0;
        for (byte b : p)
            res[i] = (byte) (b ^ c[i++]);
        return res;
    }

    private List<byte[]> getBlocks(byte[] in) {
        List<byte[]> blocks = new ArrayList<>();
        final int BLOCK_SIZE = 16;
        int mod = in.length % BLOCK_SIZE;
        int additionalLength =  mod != 0 ? BLOCK_SIZE - mod : 0;

        byte padding = 0;
        if (mod != 0) {
            padding = (byte) (BLOCK_SIZE - mod);
        }
        byte[] block = new byte[BLOCK_SIZE];

        int i;
        for (i = 0; i < in.length + additionalLength; i++) {
            if (i > 0 && i % BLOCK_SIZE == 0) {
                blocks.add(Arrays.copyOf(block, block.length));
            }
            if (i < in.length)
                block[i % BLOCK_SIZE] = in[i];
            else{
                block[i % BLOCK_SIZE] = padding;
            }
        }
        blocks.add(Arrays.copyOf(block, block.length));

        return blocks;
    }

    private byte[] deletePadding(byte[] input) {
        boolean hasPadding = checkPadding(input);
        if (hasPadding) {
            int padding = input[input.length - 1];
            byte[] tmp = new byte[input.length - padding];
            System.arraycopy(input, 0, tmp, 0, tmp.length);
            return tmp;
        }
        return input;
    }

    private boolean checkPadding(byte[] in) {
        int padding = in[in.length - 1];
        int i = in.length - 1;
        int count = 0;
        while(i >= 0 && in[i] == padding) {
            count++;
            i--;
        }
        return count == padding;
    }

}
