package encryptdecrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.util.*;
import java.util.function.IntUnaryOperator;

public class Main {
    public static void main(String[] args) {
        CliParameters parameters = new CliParameters(args);
        int key;
        try {
            key = Integer.parseInt(parameters.getVal("-key", "0"));
        } catch (Exception e) {
            error(e.getMessage());
            return;
        }

        String mode = parameters.getVal("-mode", "enc");
        String message, result = null;

        Cipher cipher;
        String alg = parameters.getVal("-alg", "shift");
        if (alg.equals("unicode")) {
            cipher = new Cipher(c -> c + key, c -> c - key);
        } else {
            ShiftMethod encrypt = new ShiftMethod(key);
            cipher = new Cipher(encrypt.encodeF(), encrypt.decodeF());
        }

        if (parameters.keyExists("-data")) {
            message = parameters.getVal("-data");
        } else if (parameters.keyExists("-in")){
            message = readFromFile(parameters.getVal("-in"));
        } else {
            message = "";
        }

        if (mode.equals("enc")) result = cipher.encrypt(message);
        else if (mode.equals("dec")) result = cipher.decrypt(message);
        else error("Wrong mode %s".formatted(mode));

        if (parameters.keyExists("-out")) {
            writeToFile(parameters.getVal("-out"), result);
        } else {
            System.out.println(result);
        }
    }

    private static String readFromFile(String filename) {
        File f = new File(filename);
        String result = "";
        try {
            Scanner in = new Scanner(new FileInputStream(f));
            while (in.hasNext()) {
                result += (in.nextLine() + "\n");
            }
            in.close();
            return result;
        } catch (Exception e) {
            error(e.getMessage());
            return "";
        }
    }
    private static void writeToFile(String filename, String text) {
        File file = new File(filename);
        try {
            FileWriter writer = new FileWriter(file);
            writer.write(text);
            writer.close();
        } catch (Exception e) {
            error("No file '%s' exists".formatted(filename));
        }
    }

    private static void error(String message) {
        System.out.print("Error: ");
        System.out.println(message);
        System.exit(0);
    }
}

class CliParameters {
    private HashMap<String, String> params;

    CliParameters (String[] args) {
        params = new HashMap<>(args.length / 2);
        int i = 0;
        while (i < args.length) {
            if (args[i].charAt(0) == '-') {
                if (i + 1 == args.length || args[i + 1].charAt(0) == '-') {
                    params.put(args[i], "");
                } else {
                    params.put(args[i], args[i + 1]);
                    i++;
                }
            }
            i++;
        }
    }

    public String getVal(String key) {
        return params.get(key);
    }
    public String getVal(String key, String defaultValue) {
        return params.getOrDefault(key, defaultValue);
    }

    public boolean keyExists(String key) {
        return params.containsKey(key);
    }
}

class Cipher {

    private IntUnaryOperator encodingF;

    private IntUnaryOperator decodingF;

    Cipher (IntUnaryOperator encodingF, IntUnaryOperator decodingF) {
        this.encodingF = encodingF;
        this.decodingF = decodingF;
    }

    Cipher (IntUnaryOperator codingF) {
        this.encodingF = codingF;
        this.decodingF = codingF;
    }

    public String encrypt (String message) {
        return new String(message.chars().map(encodingF).toArray(), 0, message.length());
    }
    public String decrypt (String message) {
        return new String(message.chars().map(decodingF).toArray(), 0, message.length());
    }
}

class ShiftMethod {
    private int key;
    private static final String alphabetLC = "abcdefghijklmnopqrstuvwxyz";
    private static final String alphabetUC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    ShiftMethod(int key) {
        this.key = key;
    }

    public IntUnaryOperator encodeF() {
        return c -> {
            String alphabet = alphabetLC;
            int i = alphabet.indexOf(c);
            if (i == -1) {
                alphabet = alphabetUC;
                i = alphabet.indexOf(c);
                if (i == -1) return c;
            }
            return alphabet.charAt((i + key) % alphabet.length());
        };
    }

    public IntUnaryOperator decodeF() {
        return c -> {
            String alphabet = alphabetLC;
            int i = alphabet.indexOf(c);
            if (i == -1) {
                alphabet = alphabetUC;
                i = alphabet.indexOf(c);
                if (i == -1) return c;
            }
            return alphabet.charAt((alphabet.length() + i - key) % alphabet.length());
        };
    }
}
