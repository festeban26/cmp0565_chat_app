public enum ExceptionManager {
    BadFormatting,
    Error,
    FileNotFoundException,
    IllegalBlockSizeException,
    InvalidAlgorithmParameterException,
    InvalidKeyException,
    InvalidKeySpecException,
    IOException,
    NoSuchAlgorithmException,
    NoSuchPaddingException,
    ParseException,
    PathDoesNotExists,
    UnsupportedEncodingException;

    void throwError(String errorMessage){
        StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
        System.out.println("WARNING: An error has occurred while the application was running.");
        System.out.println("ERROR TYPE: " + this.name() + ".");
        System.out.println("DETAILS: " + errorMessage);
        System.out.println("FROM CLASS: " +  stackTraceElements[2].getClassName());
        System.out.print("AT: " + stackTraceElements[2].getMethodName());
        System.exit(-1);
    }
}
