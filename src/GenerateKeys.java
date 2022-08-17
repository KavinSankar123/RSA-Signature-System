import java.io.*;
import java.math.BigInteger;
import java.util.Random;

public class GenerateKeys {

    public GenerateKeys() throws IOException {
        BigInteger one = new BigInteger("1");
        BigInteger X, Y, N, PHI, E, D;
        Random R = new Random();

        // Generate random prime X and Y of size 512 bits
        X = new BigInteger(512, 100, R);
        Y = new BigInteger(512, 100, R);
        N = X.multiply(Y);    // Calculate N = XY

        PHI = (X.subtract(one)).multiply(Y.subtract(one)); // Calculate PHI = (X-1)(Y-1)


        // Make sure random prime E is less than PHI and are relatively prime
        E = new BigInteger(512, 100, R);
        while ((E.compareTo(PHI) >= 0) || !(PHI.gcd(E)).equals(one))
            E = new BigInteger(1024, 100, R);


        System.out.println("Generating Keys...\n");
        System.out.println("E = " + E + "\n");


        D = E.modInverse(PHI); // get D
        System.out.println("D = " + D + "\n");


        System.out.println("N = " + N + "\n");


        System.out.println("Writing keys to files...\n");
        // Write keys to files
        ObjectOutputStream out1 = new ObjectOutputStream(new FileOutputStream("pubkey.rsa"));
        ObjectOutputStream out2 = new ObjectOutputStream(new FileOutputStream("privkey.rsa"));

        //Write the specified object to the ObjectOutputStream
        out1.writeObject(E); // write E to pubkey.rsa
        out1.writeObject(N); // write N to pubkey.rsa

        out2.writeObject(D); // write D to privkey.rsa
        out2.writeObject(N); // write N to privkey.rsa

        out1.flush(); //flushing the stream
        out1.close(); //closing the stream

        out2.flush();
        out2.close();
    }



    public static void main(String[] args) {}
    
}
