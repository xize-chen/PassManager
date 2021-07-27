package com.company;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class PassManager {
    private final static String CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!@#$%^&/?<>*_~.,:";
    private final static int LENGTH = CHARS.length();
    private final static String HASHED = "hashedMasterKey";//File name.
    private final static String TABLE = "table";//File name.
    private Scanner in;
    private HashMap<String,String> database;
    private boolean flag = true;

    /*Shuffle the character string with ThreadLocalRandom before each random password generation.
      Using System.currentTimeMillis()%10 to generate a number between 0-9,
      then shift part of the shuffled array to increase randomness.
     */
    private char[] shuffle(){
        char[] array = CHARS.toCharArray();
        Random rnd = ThreadLocalRandom.current();
        int sb = (int) (System.currentTimeMillis()%10);
        int len = array.length;
        for (int i = len - 1; i > 0; i--)
        {
            int index = rnd.nextInt(i + 1);
            if(i > sb){
                index += sb;
                if(index > i) index = index - i - 1;
            }
            int a = array[index];
            array[index] = array[i];
            array[i] = (char) a;
        }
        return array;
    }

    /*Using Cryptographically Secure Pseudo-Random Number Generator to generate random password,
      the algorithm used depends on OS. Windows-PRNG for Windows, NativePRNG for Unix like OS.
     */
    private String pwGenerator(char[] input, int length) throws NoSuchAlgorithmException {
        StringBuilder builder = new StringBuilder();
        SecureRandom secRan = SecureRandom.getInstance("Windows-PRNG");
        for(int idx=0; idx<length; idx++) {
            builder.append(input[secRan.nextInt(LENGTH)]);
        }
        return builder.toString();
    }

    //Salted hash the master password, slow hash, save the hash result and salt to a binary file.
    private void hashPass(String password){
        try{
            SecureRandom secRan = SecureRandom.getInstance("Windows-PRNG");
            byte[] salt = new byte[16];
            secRan.nextBytes(salt);
            SecretKeyFactory factory = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 512);
            byte[] hash = factory.generateSecret(spec).getEncoded();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
            outputStream.write(hash);
            outputStream.write(salt);
            byte[] data = outputStream.toByteArray( );
            fileWriter(HASHED, data);
        }catch (Exception e){
            System.out.println("Cannot hashing password!");
        }
    }

    /*Authentication method. Read the salt from saved binary file, hash again
      compare these hash results to see if they are the same.
     */
    private boolean authenticate(String input){
        try{
            byte[] data = Files.readAllBytes(Paths.get(HASHED));
            int size = data.length;
            byte[] salt = Arrays.copyOfRange(data,size-16,size);
            byte[] hashed = Arrays.copyOfRange(data,0,size-16);
            SecretKeyFactory factory = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );
            KeySpec spec = new PBEKeySpec(input.toCharArray(), salt, 65536, 512);
            byte[] hash = factory.generateSecret(spec).getEncoded();
            boolean result = Arrays.equals(hash, hashed);
            if(result) System.out.println("Correct master key!");
            else System.out.println("Wrong master key! Please try again!");
            return result;
        }catch (Exception e){System.out.println("Authentication error!");}
        return false;
    }

    private void fileWriter(String path, byte[] data){
        try(FileOutputStream fos = new FileOutputStream(path)){
            fos.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /*
    Format the data from HashMap to String.
    Using the Cipher Feedback (CFB) encryption method.
     */
    private void saveTable(String password){
        try{
            if(!database.isEmpty()){
                StringBuilder builder = new StringBuilder();
                for(String name : database.keySet()){
                    builder.append(name).append("\\").append(database.get(name)).append("\\");
                }
                String table = builder.toString();
                byte[] iv = new byte[16];
                byte[] tableSalt = new byte[16];
                SecureRandom secRan = SecureRandom.getInstance("Windows-PRNG");
                secRan.nextBytes(iv);
                secRan.nextBytes(tableSalt);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec spec = new PBEKeySpec(password.toCharArray(), tableSalt, 65536, 256);
                SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
                Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
                byte[] cipherText = cipher.doFinal(table.getBytes());
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
                outputStream.write(cipherText);
                outputStream.write(iv);
                outputStream.write(tableSalt);
                byte[] data = outputStream.toByteArray( );
                fileWriter(TABLE, data);
            }
        }catch (Exception e){
            System.out.println("Saving table error!");
        }
    }

    //Tokenize the Decrypted data into HashMap.
    private void loadTable(String password){
        try{
            File tableFile = new File(TABLE);
            if(tableFile.exists() && !tableFile.isDirectory()){
                byte[] data = Files.readAllBytes(Paths.get(TABLE));
                int size = data.length;
                byte[] tableSalt = Arrays.copyOfRange(data,size-16,size);
                byte[] iv = Arrays.copyOfRange(data,size-32,size-16);
                byte[] cipherText = Arrays.copyOfRange(data,0,size-32);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec spec = new PBEKeySpec(password.toCharArray(), tableSalt, 65536, 256);
                SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
                Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                byte[] plainText = cipher.doFinal(cipherText);
                String table = new String(plainText);
                database = new HashMap<>();
                StringTokenizer tokenizer = new StringTokenizer(table, "\\");
                while(tokenizer.hasMoreTokens()){
                    String name = tokenizer.nextToken();
                    String pw = tokenizer.nextToken();
                    database.put(name,pw);
                }
            }else database = new HashMap<>();
        } catch (Exception e) {
            System.out.println("Loading table error!");
        }
    }

    //Detects if the length of the password entered by the user is between 8 and 80.
    private int numDetect(String input){
        if (input == null) {
            return 0;
        }
        int length = input.length();
        if (length == 0 || length > 2) {
            return 0;
        }
        for(int i=0; i<length; i++){
            char c = input.charAt(i);
            if (c < '0' || c > '9')
                return 0;
        }
        int result = Integer.parseInt(input);
        if(result>7 && result<81)
            return result;
        else return 0;
    }

    private void addAccount(String app, int len){
        char[] output = shuffle();
        try{
            String pw = pwGenerator(output, len);
            database.put(app, pw);
        }catch(NoSuchAlgorithmException e) {System.out.println("Algorithm is not available on this system") ;}
    }

    //Processing user-entered commands
    private void switchCase(String command){
        switch (command.toLowerCase()) {
            case "add":
                System.out.println("Please enter an application name then press [enter].");
                String app = in.nextLine();
                System.out.println("Please enter the length of the password(8-80 *number only!*) then press [enter].");
                String len = in.nextLine();
                int length = numDetect(len);
                if(length == 0){
                    System.out.println("Invalid length of password! Please only enter number between 8 to 80.");
                }
                else {
                    addAccount(app,length);
                }
                break;
            case "find":
                if(database.isEmpty()){
                    System.out.println("No account information! Please enter a new application first!");
                }else {
                    System.out.println("Please enter an application name then press [enter].");
                    String name = in.nextLine();
                    if(database.containsKey(name)){
                        System.out.print("The password of " + name + " is: ");
                        System.out.println(database.get(name));
                    }else {
                        System.out.println("App not found!");
                        System.out.println("Apps in PassManager: ");
                        int i = 1;
                        for(String element: database.keySet()){
                            System.out.println(i + ". " + element);
                            i++;
                        }
                        System.out.println("Please select from the above list!");
                    }
                }
                break;
            case "quit":
                flag = false;
                System.out.println("Shut down.");
                break;
            default:
                System.out.println("Invalid command! Please enter: 'Add', 'Find' or 'Quit' command to execute.");
                break;
        }
    }

    private void run(){
        in = new Scanner(System.in);
        File hashFile = new File(HASHED);
        String pw;
        if(hashFile.exists() && !hashFile.isDirectory()){
            int i = 0;
            boolean ff = true;
            while(i<3 && ff){
                System.out.println("Please enter your password then press [enter].");
                pw = in.nextLine();
                boolean verified = authenticate(pw);
                if(verified) {
                    ff = false;
                    hashPass(pw);
                    loadTable(pw);
                    while (flag){
                        System.out.println("Please enter: 'Add', 'Find' or 'Quit' command to execute.");
                        String command = in.nextLine();
                        switchCase(command);
                    }
                    saveTable(pw);
                }
                i++;
            }
            if(i>2) flag = false;
        }else {
            System.out.println("Welcome! Please enter your new password then press [enter].");
            pw = in.nextLine();
            hashPass(pw);
            database = new HashMap<>();
            while (flag){
                System.out.println("Please enter: 'Add', 'Find' or 'Quit' command to execute.");
                String command = in.nextLine();
                switchCase(command);
            }
            saveTable(pw);
        }
        in.close();
    }

    public static void main(String[] args) {
        PassManager mg = new PassManager();
        mg.run();
    }
}