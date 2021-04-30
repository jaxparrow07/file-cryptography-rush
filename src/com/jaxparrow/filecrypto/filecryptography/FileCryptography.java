package com.jaxparrow.filecrypto.filecryptography;

import com.google.appinventor.components.annotations.*;
import com.google.appinventor.components.common.ComponentCategory;
import com.google.appinventor.components.common.PropertyTypeConstants;
import com.google.appinventor.components.runtime.*;
import android.os.Environment;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.util.Arrays;




public class FileCryptography extends AndroidNonvisibleComponent {

	public FileCryptography(ComponentContainer container) {
	super(container.$form());
	}


	@SimpleEvent(description = "Event raised after encrypting the file.")
	public void AfterEncrypt(String inputfile, String outputfile,String key) {
	    EventDispatcher.dispatchEvent(this, "AfterEncrypt", inputfile,outputfile,key);
	}

	@SimpleEvent(description = "Event raised after decrypting the file.")
	public void AfterDecrypt(String inputfile, String outputfile,String key) {
	    EventDispatcher.dispatchEvent(this, "AfterDecrypt", inputfile,outputfile,key);
	}

	@SimpleEvent(description = "Event raised after encrypting failed.")
	public void OnEncryptFail(String error, int code) {
	    EventDispatcher.dispatchEvent(this, "OnEncryptFail", error,code);
	}

	@SimpleEvent(description = "Event raised after decrypting failed.")
	public void OnDecryptFail(String error, int code) {
	    EventDispatcher.dispatchEvent(this, "OnDecryptFail", error,code);
	}

	@SimpleFunction(description = "Encrypts input file and save it as encrypted file using the provided key")
	public void EncryptFile(String inputfile, String outputfile, String key) {
       try {
              encrypt(inputfile,outputfile,key);
       } catch (InvalidKeyException e) {
              e.printStackTrace();
              OnEncryptFail("InvalidKeyException",1);
       } catch (NoSuchAlgorithmException e) {
              OnEncryptFail("NoSuchAlgorithmException",2);
              e.printStackTrace();
       } catch (NoSuchPaddingException e) {
              OnEncryptFail("NoSuchPaddingException",3);
              e.printStackTrace();
       } catch (IOException e) {
              OnEncryptFail("IOException",4);
              e.printStackTrace();
       }
	}

	@SimpleFunction(description = "Decrypts input file and save it as decrypted file using the provided key")
	public void DecryptFile(String inputfile, String outputfile, String key) {

       try {
              decrypt(inputfile,outputfile,key);
       } catch (InvalidKeyException e) {
              e.printStackTrace();
              OnDecryptFail("InvalidKeyException",1);
       } catch (NoSuchAlgorithmException e) {
              OnDecryptFail("NoSuchAlgorithmException",2);
              e.printStackTrace();
       } catch (NoSuchPaddingException e) {
              OnDecryptFail("NoSuchPaddingException",3);
              e.printStackTrace();
       } catch (IOException e) {
              OnDecryptFail("IOException",4);
              e.printStackTrace();
       }
	}

/**
    * Here is Both function for encrypt and decrypt file in Sdcard folder. we
    * can not lock folder but we can encrypt file using AES in Android, it may
    * help you.
    *
    * @throws IOException
    * @throws NoSuchAlgorithmException
    * @throws NoSuchPaddingException
    * @throws InvalidKeyException
    */
	public void encrypt(String ifile, String ofile, String okey) throws IOException, NoSuchAlgorithmException,
                 NoSuchPaddingException, InvalidKeyException {



  		  byte[] tkey = okey.getBytes("UTF-8");
		  MessageDigest sha = MessageDigest.getInstance("SHA-1");
		  tkey = sha.digest(tkey);
		  tkey = Arrays.copyOf(tkey, 16); // use only first 128 bit

          // Here you read the cleartext.
          FileInputStream fis = new FileInputStream(ifile);
          // This stream write the encrypted text. This stream will be wrapped by
          // another stream.
          FileOutputStream fos = new FileOutputStream(ofile);

          // Length is 16 byte
          SecretKeySpec sks = new SecretKeySpec(tkey,"AES");
          // Create cipher
          Cipher cipher = Cipher.getInstance("AES");
          cipher.init(Cipher.ENCRYPT_MODE, sks);
          // Wrap the output stream
          CipherOutputStream cos = new CipherOutputStream(fos, cipher);
          // Write bytes
          int b;
          byte[] d = new byte[8];
          while ((b = fis.read(d)) != -1) {
                 cos.write(d, 0, b);
          }
          // Flush and close streams.
          cos.flush();
          cos.close();
          fis.close();
          AfterEncrypt(ifile,ofile,okey);

   }

   public void decrypt(String ifile, String ofile, String okey) throws IOException, NoSuchAlgorithmException,
                 NoSuchPaddingException, InvalidKeyException {


  		  byte[] tkey = okey.getBytes("UTF-8");
		  MessageDigest sha = MessageDigest.getInstance("SHA-1");
		  tkey = sha.digest(tkey);
		  tkey = Arrays.copyOf(tkey, 16); // use only first 128 bitit

          FileInputStream fis = new FileInputStream(ifile);

          FileOutputStream fos = new FileOutputStream(ofile);

          SecretKeySpec sks = new SecretKeySpec(tkey,"AES");
          Cipher cipher = Cipher.getInstance("AES");
          cipher.init(Cipher.DECRYPT_MODE, sks);
          CipherInputStream cis = new CipherInputStream(fis, cipher);
          int b;
          byte[] d = new byte[8];
          while ((b = cis.read(d)) != -1) {
                 fos.write(d, 0, b);
          }
          fos.flush();
          fos.close();
          cis.close();
          AfterDecrypt(ifile,ofile,okey);

   }

}