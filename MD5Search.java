import java.security.MessageDigest;
import java.math.BigInteger;

public class MD5Search {
    // Shared flag for thread coordination (Requirement e)
    public static volatile boolean isFound = false;

    public static void main(String[] args) throws InterruptedException {
        // 1. CLI Input Validation
        if (args.length != 3) {
            System.out.println("Usage: java MD5Search <hash> <threads> <passwordLength>");
            return;
        }

        String targetHash = args[0];
        int numThreads = 0;
        int passwordLength = 0;

        try {
            numThreads = Integer.parseInt(args[1]);
            passwordLength = Integer.parseInt(args[2]);
        } catch (NumberFormatException e) {
            System.out.println("Error: Threads and password length must be integers.");
            return;
        }

        // Enforce thread limit (Requirement c & g)
        if (numThreads < 1 || numThreads > 10) {
            System.out.println("Error: Number of threads must be between 1 and 10.");
            return;
        }

        long startTime = System.currentTimeMillis();

        // 2. Search-Space Partitioning
        int totalChars = 95; // ASCII 32 to 126
        int baseShare = totalChars / numThreads;
        int remainder = totalChars % numThreads;

        Thread[] threads = new Thread[numThreads];
        int startAscii = 32;

        for (int i = 0; i < numThreads; i++) {
            int endAscii = startAscii + baseShare - 1;
            
            // Distribute remainder so no characters are missed
            if (remainder > 0) {
                endAscii++;
                remainder--;
            }

            // 3. Thread Creation
            threads[i] = new SearchWorker(targetHash, startAscii, endAscii, passwordLength, i + 1);
            threads[i].start();

            // Next thread picks up exactly where this one left off
            startAscii = endAscii + 1; 
        }

        // Main program waits for all workers to terminate
        for (int i = 0; i < numThreads; i++) {
            threads[i].join();
        }

        long endTime = System.currentTimeMillis();
        System.out.println("Total Execution Time: " + (endTime - startTime) + " ms");
    }
}

// Worker Class extending Thread
class SearchWorker extends Thread {
    private String targetHash;
    private int startAscii;
    private int endAscii;
    private int maxLength;
    private int threadId;

    public SearchWorker(String targetHash, int startAscii, int endAscii, int maxLength, int threadId) {
        this.targetHash = targetHash;
        this.startAscii = startAscii;
        this.endAscii = endAscii;
        this.maxLength = maxLength;
        this.threadId = threadId;
    }

    @Override
    public void run() {
        // The outermost loop is restricted to this specific thread's assigned ASCII range
        for (int i = startAscii; i <= endAscii; i++) {
            if (MD5Search.isFound) return;
            generateAndCheck(Character.toString((char) i), 1);
        }
    }

    // Recursive function replaces the hardcoded nested loops from Appendix A
    private void generateAndCheck(String currentString, int currentLength) {
        // Early termination check
        if (MD5Search.isFound) return;

        if (currentLength == maxLength) {
            if (getMd5(currentString).equals(targetHash)) {
                System.out.println("Password found: " + currentString);
                System.out.println("Found by Thread ID: " + threadId);
                MD5Search.isFound = true; // Signal all other threads to stop
            }
            return;
        }

        // Inner character positions loop through the full ASCII 32-126 range
        for (int i = 32; i <= 126; i++) {
            if (MD5Search.isFound) return;
            generateAndCheck(currentString + (char) i, currentLength + 1);
        }
    }

    // Original MD5 logic from Appendix A
    private String getMd5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(input.getBytes());
            BigInteger no = new BigInteger(1, messageDigest);
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}