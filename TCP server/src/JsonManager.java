package com.company;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class JsonManager {


    public static ArrayList<UserCredential> readData(String filename){
        try{
            ArrayList<UserCredential> userCredentialsArrayList = new ArrayList<>();
            JSONParser parser = new JSONParser();
            Reader reader = new FileReader(filename); // Puede ser optimizado leyendo por Buffers
            Object obj = parser.parse(reader);
            JSONArray jsonArray = (JSONArray) obj;
            for (Object element : jsonArray){
                JSONObject jsonObject = (JSONObject) element;
                String username = (String) jsonObject.get("username");
                String password = (String) jsonObject.get("password");
                UserCredential userCredential = new UserCredential(username, password);
                userCredentialsArrayList.add(userCredential);
            }
            return userCredentialsArrayList;

        } catch (FileNotFoundException e) {
            String errorMessage = "The file \"" + filename + "\" could not be found.";
            ExceptionManager.FileNotFoundException.throwError(errorMessage);
        } catch (IOException e) {
            String errorMessage = "IO exception.";
            ExceptionManager.IOException.throwError(errorMessage);
        } catch (ParseException e) {
            String errorMessage = "Parse exception.";
            ExceptionManager.ParseException.throwError(errorMessage);
        }
        return null;
    }

    public static void writeData(ArrayList<UserCredential> userCredentials, String filename, Charset charset){

        BufferedWriter out = null;
        try {
            out = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(filename), charset));
            out.write("[");
            StringBuilder sb = new StringBuilder();
            for(UserCredential userCredential : userCredentials){
                sb.append("\n\t{\n\t\"username\":\"");
                sb.append(userCredential.getUsername());
                sb.append("\",\n\t\"password\":\"");
                sb.append(userCredential.getPassword());
                sb.append("\"\n\t}");
                if(userCredentials.indexOf(userCredential) < userCredentials.size() - 1)
                    sb.append(",");

                out.write(sb.toString());
                sb.setLength(0);
            }
            out.write("]");
            out.flush();
        } catch (UnsupportedEncodingException e) {
            String errorMessage = "The charset " + charset.toString() + " is not supported by the system.";
            ExceptionManager.UnsupportedEncodingException.throwError(errorMessage);
        } catch (FileNotFoundException e) {
            String errorMessage = "The file \"" + filename + "\" could not be found.";
            ExceptionManager.FileNotFoundException.throwError(errorMessage);
        } catch (IOException e) {
            String errorMessage = "IO exception.";
            ExceptionManager.IOException.throwError(errorMessage);
        }finally {
            if(out != null)
                try { out.close(); }
                catch (IOException e) {
                    String errorMessage = "IO exception.";
                    ExceptionManager.IOException.throwError(errorMessage);
                }
        }
    }
}
