import java.nio.charset.Charset;

// Proof of work manager
public class PowManager {

    private String hashAlgorithm;
    private Charset charset;
    private HashingManager hashingManager;

    public PowManager(String hashAlgorithm, Charset charset){
        this.hashAlgorithm = hashAlgorithm;
        this.charset = charset;
        this.hashingManager = new HashingManager(hashAlgorithm, charset);
    }

    public boolean checkPow(int nBits, int base, int nonceToAppend){

        byte[] hash;
        String text;

        text = Integer.toString(base) + Integer.toString(nonceToAppend);
        hash = this.hashingManager.hash_asByteArray(text);
        String hash_AsStringRepresentation = "";

        for (byte b : hash)
            hash_AsStringRepresentation += Integer.toBinaryString(b & 255 | 256).substring(1);

        String testString = "";

        for(int i = 0; i < nBits; i ++)
            testString += "0";

        if(testString.equalsIgnoreCase(hash_AsStringRepresentation.substring(0, nBits))){ return true; }
        else return false;
    }

    public int doPow(int nBits, int nonceToAppend){

        boolean exit = false;
        int counter = 0;
        byte[] hash;
        String text;

        do {
            text = Integer.toString(counter) + Integer.toString(nonceToAppend);
            hash = this.hashingManager.hash_asByteArray(text);
            String hash_AsStringRepresentation = "";

            for (byte b : hash)
                hash_AsStringRepresentation += Integer.toBinaryString(b & 255 | 256).substring(1);

            String testString = "";

            for(int i = 0; i < nBits; i ++)
                testString += "0";

            if(testString.equalsIgnoreCase(hash_AsStringRepresentation.substring(0, nBits)))
                exit = true;
            else { counter ++; }
        }while (exit == false);
        return counter;
    }
}