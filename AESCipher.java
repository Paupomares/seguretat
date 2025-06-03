package uib.sec.project.crypto;


import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCipher {

    private Cipher cEncrypt;
    private Cipher cDecrypt;

    public AESCipher(byte[] aesKeyBytes, byte[] ivBytes, String algMode) throws Exception {
        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        cEncrypt = Cipher.getInstance(algMode);
        cEncrypt.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

        cDecrypt = Cipher.getInstance(algMode);
        cDecrypt.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
    }

    public Cipher getEncryptCipher() {
        return cEncrypt;
    }

    public Cipher getDecryptCipher() {
        return cDecrypt;
    }
}

