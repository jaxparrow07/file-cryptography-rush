package com.jaxparrow.filecrypto.filecryptography;

import com.google.appinventor.components.annotations.*;
import com.google.appinventor.components.common.ComponentCategory;
import com.google.appinventor.components.common.PropertyTypeConstants;
import com.google.appinventor.components.runtime.*;
import com.google.appinventor.components.runtime.errors.YailRuntimeError;
import com.google.appinventor.components.runtime.util.TextViewUtil;


import android.os.Environment;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;





public class FileCryptography extends AndroidNonvisibleComponent {

       public boolean abs_path = false;
       public String f_key = "!z%C*F-JaNdRgUkX"; // Default Key to avoid Exception

	public FileCryptography(ComponentContainer container) {
	super(container.$form());
	}

       @SimpleProperty(description = "")
       public void UseAbsolutePath(boolean abs){
        this.abs_path = abs;
       }

       @SimpleProperty(description = "")
       public boolean UseAbsolutePath(){
           return this.abs_path;
       }


       @SimpleProperty(description = "Sets the key for Encryption/Decryption")
       public void Key(String str){
        this.f_key = str;
       }


       @SimpleProperty(description = "Returns the current Encryption/Decryption Key")
       public String Key(){
        return this.f_key;
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
	public void EncryptFile(String path, String output) {
       try {
              encrypt(path,output,this.f_key);
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
	public void DecryptFile(String path, String output) {

       try {
              decrypt(path,output,this.f_key);
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
    *
    *
    * @throws IOException
    * @throws NoSuchAlgorithmException
    * @throws NoSuchPaddingException
    * @throws InvalidKeyException
    */
	public void encrypt(String ifile, String ofile, String okey) throws IOException, NoSuchAlgorithmException,
                 NoSuchPaddingException, InvalidKeyException {


          File extStore = Environment.getExternalStorageDirectory();

          FileInputStream fis;
          FileOutputStream fos;

          if (!this.abs_path) {
                 fis = new FileInputStream(extStore + ifile);
                 fos = new FileOutputStream(extStore + ofile);
          } else {
              fis = new FileInputStream(ifile);
              fos = new FileOutputStream(ofile);
          }
          SecretKeySpec sks = new SecretKeySpec(okey.getBytes(),"AES");
          Cipher cipher = Cipher.getInstance("AES");
          cipher.init(Cipher.ENCRYPT_MODE, sks);
          CipherOutputStream cos = new CipherOutputStream(fos, cipher);
          int b;
          byte[] d = new byte[8];
          while ((b = fis.read(d)) != -1) {
                 cos.write(d, 0, b);
          }
          cos.flush();
          cos.close();
          fis.close();
          AfterEncrypt(ifile,ofile,okey);

   }

   public void decrypt(String ifile, String ofile, String okey) throws IOException, NoSuchAlgorithmException,
                 NoSuchPaddingException, InvalidKeyException {

          File extStore = Environment.getExternalStorageDirectory();

          FileInputStream fis;
          FileOutputStream fos;

          if (!this.abs_path) {
              fis = new FileInputStream(extStore + ifile);
              fos = new FileOutputStream(extStore + ofile);
          } else {
              fis = new FileInputStream(ifile);
              fos = new FileOutputStream(ofile);
          }

          SecretKeySpec sks = new SecretKeySpec(okey.getBytes(),"AES");
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
