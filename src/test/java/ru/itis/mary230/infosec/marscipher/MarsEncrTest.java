package ru.itis.mary230.infosec.marscipher;

import org.apache.commons.codec.binary.Hex;
import ru.itis.mary230.infosec.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MarsEncrTest extends Test {

    @org.junit.jupiter.api.Test
    public void encoderTest1() {
        var expectedResult = "B3E2AD5608AC1B6733A7CB4FDF8F9952";
        var key = "80000000000000000000000000000000";
        var in = "00000000000000000000000000000000";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new Mars(keyBytes);
        var result = Hex.encodeHexString(mars.blockE(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @org.junit.jupiter.api.Test
    public void encoderTest2() {
        var expectedResult = "33CAFFBDDC7F1DDA0F9C15FA2F30E2FF";
        var key = "00000000000000000000000000000000";
        var in = "DCC07B8DFB0738D6E30A22DFCF27E886";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new Mars(keyBytes);
        var result = Hex.encodeHexString(mars.blockE(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @org.junit.jupiter.api.Test
    public void encoderTest3() {
        var expectedResult = "225DA2CB64B73F79069F21A5E3CB8522";
        var key = "CB14A1776ABBC1CDAFE7243DEF2CEA02";
        var in = "F94512A9B42D034EC4792204D708A69B";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new Mars(keyBytes);
        var result = Hex.encodeHexString(mars.blockE(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

}
