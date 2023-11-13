package com.example.TestSpringBootApp.Util;

import org.springframework.http.HttpStatus;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;

public class Util {

    public static String[] users = {"admin", "yusuf", "ruby"};
    public static String[] pass =  {"admin", "yusuf", "ruby"};
    public static String[] role =  {"admin", "admin", "admin"};
    private static String LICENSE_IV = "4f674951b97c7fb0";
    private static String LICENSE_SALT = "f9thsu";
    private static String LICENSE_ALGORITHM = "AES";
    private static String LICENSE_SECRETKEY = "f988a1708e3e3286688a36f14344e4bc";

    public static String encrypt(String strToEncrypt) {
        try {
            IvParameterSpec ivspec = new IvParameterSpec(LICENSE_IV.getBytes("UTF-8"));

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(LICENSE_SECRETKEY.toCharArray(), LICENSE_SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), LICENSE_ALGORITHM);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static void checkImageFile(MultipartFile file) {
        String contentType = file.getContentType();
        if(!contentType.equals("image/jpg") && !contentType.equals("image/jpeg") && !contentType.equals("image/png") &&
                !contentType.equals("image/gif") && !contentType.equals("image/svg")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Illegal file format");
        }
        var ext = file.getOriginalFilename().split("\\.");
        if (ext.length > 2) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Illegal file extension");
        }
        if(file.getSize() > 5e+6) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "File size too long");
        }
    }
}
