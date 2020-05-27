package ru.itis.mary230.infosec.marscipher;

import org.apache.commons.codec.binary.Hex;
import ru.itis.mary230.infosec.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MarsDecTest extends Test {

    @org.junit.jupiter.api.Test
    public void decoderTest1() {
        var expectedResult = "00000000000000000000000000000000";
        var key = "80000000000000000000000000000000";
        var in = "B3E2AD5608AC1B6733A7CB4FDF8F9952";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new Mars(keyBytes);
        var result = Hex.encodeHexString(mars.blockD(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @org.junit.jupiter.api.Test
    public void decoderTest2() {
        var expectedResult = "F94512A9B42D034EC4792204D708A69B";
        var key = "CB14A1776ABBC1CDAFE7243DEF2CEA02";
        var in = "225DA2CB64B73F79069F21A5E3CB8522";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new Mars(keyBytes);
        var result = Hex.encodeHexString(mars.blockD(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @org.junit.jupiter.api.Test
    public void encoderTest3() {
        var in = "225DA2CB64B73F79069F21A5E3CB8522";
        var key = "CB14A1776ABBC1CDAFE7243DEF2CEA02";
        var expectedResult = "F94512A9B42D034EC4792204D708A69B";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new Mars(keyBytes);
        var result = Hex.encodeHexString(mars.blockD(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @org.junit.jupiter.api.Test
    public void encoderTest4() {
        var in = "DCC07B8DFB0738D6E30A22DFCF27E886";
        var key = "00000000000000000000000000000000";
        var expectedResult = "00000000000000000000000000000000";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new Mars(keyBytes);
        var result = Hex.encodeHexString(mars.blockD(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @org.junit.jupiter.api.Test
    public void encoderTest5() {
        var expectedResult = "00000000000000000000000000000000";
        var key = "00000000000000000000000000000000";
        var in = "DCC07B8DFB0738D6E30A22DFCF27E886";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new Mars(keyBytes);
        var result = Hex.encodeHexString(mars.blockD(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

}
