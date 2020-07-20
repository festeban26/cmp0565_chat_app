package com.company;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileManager {

    // Function to test if a file exist
    public static boolean doesFileExist(String filePath){

        Path tempFilePath;

        /*If the filePath contains a OS separator character, it means that the user has given
        us the full path of the file. */
        if (filePath.contains(File.separator))
            tempFilePath = Paths.get(filePath);
        // else, the file is located on the current directory
        else {
            // Gets the path to current directory
            Path currentDirectoryPath = Paths.get(System.getProperty("user.dir"));
            // set to tempFilePath to the full path of the file (including current directory).
            tempFilePath = currentDirectoryPath.resolve(filePath);
        }

        // The file exist
        if (tempFilePath.toFile().exists() && !tempFilePath.toFile().isDirectory())
            return true;
        else return false;
    }

    public static boolean doesPathExist(String path){

        Path tempPath;
        /*If the path contains a OS separator character, it means that the user has given
        us a full path. */
        if (path.contains(File.separator))
            tempPath = Paths.get(path);
        // else, the file is located on the current directory
        else {
            // Gets the path to current directory
            Path currentDirectoryPath = Paths.get(System.getProperty("user.dir"));
            // set to tempFilePath to the full path of the file (including current directory).
            tempPath = currentDirectoryPath.resolve(path);
        }

        // check if path exists
        if(Files.exists(tempPath))
            return true;
        else return false;
    }

    public static Path getPathOfFile(String file) {

        Path tempFilePath;

        /*If the filePathString contains a OS separator character, it means that the user has given
        us the full path of the file. */
        if (file.contains(File.separator)) {
            // We assume that the user has given us a full path to a file
            tempFilePath = Paths.get(file);
        }
        // else, the file is located on the current directory
        else {
            // Gets the path to current directory
            Path currentDirectoryPath = Paths.get(System.getProperty("user.dir"));
            // set to tempFilePath to the full path of the file (including current directory).
            tempFilePath = currentDirectoryPath.resolve(file);
        }

        if(FileManager.doesFileExist(file))
            return tempFilePath;
        String errorMessage = "The file \"" + file + "\" could not be found.";
        ExceptionManager.FileNotFoundException.throwError(errorMessage);
        return null; // Unreachable code since ExceptionManager exits the program.
    }

}
