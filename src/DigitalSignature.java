import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.Scanner;


public class DigitalSignature {


    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ClassNotFoundException {
        GenerateKeys generateKeys = new GenerateKeys();
        sender();
        receiver();
        changeByte();

        System.out.print("Do you wish to send the tampered file? Enter 'Y' or 'N': ");

        Scanner scanner = new Scanner(System.in);
        if (scanner.next().equals("Y")) {
            System.out.println("\n");
            receiver();
        }

        System.out.println("\n");
        System.out.println("--------Now testing validity of file when changing byte in Big Integer Object of signed file------\n\n");

        sender();
        receiver();
        changeByte();
        receiver();
    }

    public static void changeByte() throws IOException, NoSuchAlgorithmException, ClassNotFoundException {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Do you wish to tamper with the signed file? enter 'Y' or 'N': ");
        String input = scanner.next();
        System.out.println();

        if (input.equals("N"))
            System.exit(0);

        try {
            System.out.print("Enter file name: ");
            Scanner scanner1 = new Scanner(System.in);
            String fileName = scanner1.nextLine();

            RandomAccessFile randomAF = new RandomAccessFile(fileName, "rw");

            DataInputStream inputStream = new DataInputStream(new FileInputStream(fileName));
            int numBytes = inputStream.available();

            System.out.println();
            System.out.print("Enter byte to change (0 and " + (numBytes - 1) + " inclusive): ");
            int byteIndex = scanner.nextInt();
            randomAF.seek(byteIndex); // move file pointer to byteIndex

            Random random = new Random();
            int randomChar = random.nextInt(256);


            System.out.println("Writing random character '" + (char) randomChar + "' to " + fileName + " at index " + byteIndex + "...\n");
            randomAF.writeByte(randomChar);

            randomAF.close();
            inputStream.close();

        } catch (IOException e) {
            System.out.println("Input file does not exist. Please run program again");
        }
    }


    public static void sender() throws NoSuchAlgorithmException, IOException, ClassNotFoundException {
        DataInputStream inputStream = new DataInputStream(new FileInputStream("test.txt"));


        System.out.println("Printing test file: test.txt");
        System.out.println("--------------------");
        DataInputStream printFile = new DataInputStream(new FileInputStream("test.txt"));
        int k = printFile.available();
        for (int j = 0; j < k; j++) {
            System.out.print((char) printFile.readByte());
        }
        System.out.println();
        System.out.println("--------------------\n");

        System.out.print("Do you wish to send the file? Enter 'Y' or 'N': ");
        Scanner scanner = new Scanner(System.in);
        if (scanner.next().equals("N")) {
            System.exit(0);
        }
        System.out.println();
        System.out.println("Now sending test.txt...\n");


        byte[] b1 = new byte[inputStream.available()];
        int counter = inputStream.available();

        for (int i = 0; i < counter; i++) // turn input file's text into byte array
            b1[i] = inputStream.readByte();
        inputStream.close();


        MessageDigest m1 = MessageDigest.getInstance("SHA-256");
        m1.update(b1);
        byte[] digest1 = m1.digest();  // Completing digests / signatures

        BigInteger signature = new BigInteger(1, digest1); // convert to BigInteger


        ObjectInputStream in1 = new ObjectInputStream(new FileInputStream("privkey.rsa"));
        BigInteger D = (BigInteger) in1.readObject(); // D = decryption key
        BigInteger N = (BigInteger) in1.readObject(); // N = (X)(Y)
        BigInteger M = signature.modPow(D, N); // Now decrypt the message --> M = (C^D) mod N
        in1.close();

        ObjectOutputStream out1 = new ObjectOutputStream(new FileOutputStream("test.txt.signed"));
        out1.writeObject(M);

        // write to file byte by byte
        for (byte b : b1) {
            out1.writeByte(b);
        }
        out1.close();


        System.out.println("Printing signed file: test.txt.signed");
        System.out.println("-----------------------------------------");
        ObjectInputStream readBigInt = new ObjectInputStream(new FileInputStream("test.txt.signed"));
        System.out.println(readBigInt.readObject());

        while (readBigInt.available() > 0)
            System.out.print((char) readBigInt.readByte());
        System.out.println();
        System.out.println("-----------------------------------------\n");
    }


    public static void receiver() throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        ObjectInputStream in1;
        ObjectInputStream in2;

        System.out.println("Receiving the signed file...\n");

        try {
            in1 = new ObjectInputStream(new FileInputStream("test.txt.signed"));
            in2 = new ObjectInputStream(new FileInputStream("pubkey.rsa"));


            System.out.println("Printing the received signed file: test.txt.signed");
            System.out.println("--------------------------------");

            ObjectInputStream readBigInt = new ObjectInputStream(new FileInputStream("test.txt.signed"));
            System.out.println(readBigInt.readObject());

            while (readBigInt.available() > 0)
                System.out.print((char) readBigInt.readByte());
            System.out.println();

            System.out.println("-----------------------------------------\n");



            BigInteger E = (BigInteger) in2.readObject();
            BigInteger N = (BigInteger) in2.readObject();
            BigInteger message = (BigInteger) in1.readObject();
            in2.close();

            BigInteger M = message.modPow(E, N); // C = (M^E) mod N
            byte[] signature = M.toByteArray();


            byte[] messageBytes = new byte[in1.available()];

            int counter = in1.available();
            for (int i = 0; i < counter; i++)
                messageBytes[i] = in1.readByte();

            in1.close();

            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(messageBytes);
            byte[] digest1 = messageDigest.digest();


            BigInteger M1 = new BigInteger(1, signature);
            BigInteger digest = new BigInteger(1, digest1);


            if (M.equals(digest)) {
                System.out.println("The received file is valid OR there was a collision\n");
            } else {
                System.out.println("The message was invalid. Someone has tampered with the file\n");
            }
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("File has been corrupted. Big Integer Object was not read properly");
        }
    }
}