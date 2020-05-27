package ru.itis.mary230.infosec.mode;

import org.apache.commons.codec.binary.Hex;
import ru.itis.mary230.infosec.Test;
import ru.itis.mary230.infosec.marscipher.Mars;

import java.math.BigInteger;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

class OFBCipherModeTest extends Test {

    @org.junit.jupiter.api.Test
    void applyMode1() {
        var key = "80000000000000000000000000000000";
        var in = "00000000000000000000000000000000";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var ofbEncryptionMode = new OFBCipherMode();
        var mars = new Mars(keyBytes);
        var initVector = generateInitVector();

        var encResult = Hex.encodeHexString(ofbEncryptionMode.encryptWithMode(inBytes, mars::blockE, initVector));
        var decResult = Hex.encodeHexString(ofbEncryptionMode.decryptWithMode(hexToByte(encResult), mars::blockE, initVector));

        assertNotNull(encResult);
        assertNotNull(decResult);
        assertEquals(in, decResult.toUpperCase());
    }

    @org.junit.jupiter.api.Test
    void applyMode2() {
        var key = "CB14A1776ABBC1CDAFE7243DEF2CEA02";
        var in = "F94512A9B42D034EC4792204D708A69B";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var ofbCipherMode = new OFBCipherMode();
        var mars = new Mars(keyBytes);
        var initVector = generateInitVector();

        var encResult = Hex.encodeHexString(ofbCipherMode.encryptWithMode(inBytes, mars::blockE, initVector));
        var decResult = Hex.encodeHexString(ofbCipherMode.decryptWithMode(hexToByte(encResult), mars::blockE, initVector));

        assertNotNull(encResult);
        assertNotNull(decResult);
        assertEquals(in, decResult.toUpperCase());
    }

    @org.junit.jupiter.api.Test
    void applyMode3() {
        var key = "00000000000000000000000000000000";
        var in = "00000000000000000000000000000000";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var ofbCipherMode = new OFBCipherMode();
        var mars = new Mars(keyBytes);
        var initVector = generateInitVector();

        var encResult = Hex.encodeHexString(ofbCipherMode.encryptWithMode(inBytes, mars::blockE, initVector));
        var decResult = Hex.encodeHexString(ofbCipherMode.decryptWithMode(hexToByte(encResult), mars::blockE, initVector));

        assertNotNull(encResult);
        assertNotNull(decResult);
        assertEquals(in, decResult.toUpperCase());
    }

    public byte[] generateInitVector() {
        byte[] result = new byte[16];
        var time = LocalDateTime.now();
        var weekday = time.getDayOfYear();
        var hours = time.getHour();
        var minutes = time.getMinute();
        var seconds = time.getSecond();

        var first4Bytes = BigInteger.valueOf(weekday).toByteArray();
        var second4Bytes = BigInteger.valueOf(hours).toByteArray();
        var third4Bytes = BigInteger.valueOf(minutes).toByteArray();
        var fourth4Bytes = BigInteger.valueOf(seconds).toByteArray();

        System.arraycopy(first4Bytes, 0, result, 4 - first4Bytes.length % 4, first4Bytes.length);
        System.arraycopy(second4Bytes, 0, result, 8 - second4Bytes.length % 4, second4Bytes.length);
        System.arraycopy(third4Bytes, 0, result, 12 - third4Bytes.length % 4, third4Bytes.length);
        System.arraycopy(fourth4Bytes, 0, result, 16 - fourth4Bytes.length % 4, fourth4Bytes.length);

        return result;
    }
}