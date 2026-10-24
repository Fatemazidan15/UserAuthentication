/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package passwordauthentication;

/**
 *
 * @author Pc World
 */

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.List;
import java.util.Scanner;

public class PasswordAuthentication {

    private static final Path FILE_PATH =
            Paths.get("users.txt");

    private static final SecureRandom RANDOM =
            new SecureRandom();

    private static String generateSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return toHex(salt);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();

        for (byte b : bytes) {
            result.append(String.format("%02x", b & 0xff));
        }

        return result.toString();
    }

    private static String hashPassword(
            String password, String salt) throws Exception {

        MessageDigest digest =
                MessageDigest.getInstance("SHA-256");

        byte[] hash = digest.digest(
                (password + salt).getBytes(StandardCharsets.UTF_8));

        return toHex(hash);
    }

    private static boolean userExists(String username)
            throws IOException {

        if (!Files.exists(FILE_PATH)) {
            return false;
        }

        List<String> lines = Files.readAllLines(
                FILE_PATH, StandardCharsets.UTF_8);

        for (String line : lines) {
            String[] parts = line.split(":", -1);

            if (parts.length == 3 &&
                    parts[0].equals(username)) {
                return true;
            }
        }

        return false;
    }

   
    private static void register(
            String username, String password) throws Exception {

        if (userExists(username)) {
            System.out.println("Username already exists.");
            return;
        }

        String salt = generateSalt();
        String hash = hashPassword(password, salt);

        String record = username + ":" + salt + ":" + hash
                + System.lineSeparator();

        Files.write(
                FILE_PATH,
                record.getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
        );

        System.out.println("Registration successful.");
    }


    private static void login(
            String username, String password) throws Exception {

        if (!Files.exists(FILE_PATH)) {
            System.out.println("No registered users found.");
            return;
        }

        List<String> lines = Files.readAllLines(
                FILE_PATH, StandardCharsets.UTF_8);

        for (String line : lines) {
            String[] parts = line.split(":", -1);

            if (parts.length == 3 &&
                    parts[0].equals(username)) {

                String salt = parts[1];
                String storedHash = parts[2];

                String enteredHash =
                        hashPassword(password, salt);

                if (MessageDigest.isEqual(
                        enteredHash.getBytes(StandardCharsets.UTF_8),
                        storedHash.getBytes(StandardCharsets.UTF_8))) {

                    System.out.println("Login successful.");
                } else {
                    System.out.println("Incorrect password.");
                }

                return;
            }
        }

        System.out.println("Username not found.");
    }

    public static void main(String[] args) {
        Scanner input = new Scanner(System.in);

        try {
            while (true) {
                System.out.println("\n1. Register");
                System.out.println("2. Login");
                System.out.println("3. Exit");
                System.out.print("Choose an option: ");

                String choice = input.nextLine();

                if (choice.equals("1")) {
                    System.out.print("Enter username: ");
                    String username = input.nextLine();

                    System.out.print("Enter password: ");
                    String password = input.nextLine();

                    register(username, password);

                } else if (choice.equals("2")) {
                    System.out.print("Enter username: ");
                    String username = input.nextLine();

                    System.out.print("Enter password: ");
                    String password = input.nextLine();

                    login(username, password);

                } else if (choice.equals("3")) {
                    System.out.println("Goodbye!");
                    break;

                } else {
                    System.out.println("Invalid option.");
                }
            }

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }

        input.close();
    }
}

