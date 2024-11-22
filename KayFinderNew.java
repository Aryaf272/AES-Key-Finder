import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class KayFinderNew {
    public static void main(String[] args) {
        try {
            // hex
            String ciphertextHex = "764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2";
            byte[] iv = hexStringToByteArray("aabbccddeeff00998877665544332211"); 
            byte[] ciphertext = hexStringToByteArray(ciphertextHex);

            // read words.txt
            List<String> words = Files.readAllLines(Paths.get("file path"));
            String foundKey = null;

            for (String word : words) {
                String keyString = String.format("%-16s", word).replace(' ', '#');

                try {
                    String decryptedText = decrypt(ciphertext, keyString, iv);
                    if (decryptedText.equals("This is a top secret.")) {
                        System.out.println("Found key: " + keyString);
                        foundKey = keyString;
                        break; 
                    }
                } catch (Exception e) {
                    
                }
            }

            if (foundKey != null) {
                
                String plaintext = "This is a top secret.";
                byte[] encryptedText = encrypt(plaintext, foundKey, iv);
                System.out.println("Encrypted Text: " + byteArrayToHexString(encryptedText));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String decrypt(byte[] ciphertext, String keyString, byte[] iv) throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyString.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        return new String(decrypted).trim(); 
    }

    private static byte[] encrypt(String plaintext, String keyString, byte[] iv) throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyString.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(plaintext.getBytes());
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
