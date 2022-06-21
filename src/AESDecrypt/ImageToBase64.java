package AESDecrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

public class ImageToBase64 {
//	public static void main(String[] args) throws IOException {
//		String imagePath = "D:\\usr\\haha.png";
//		System.out.println("=================Encoder Image to Base 64!=================");
////		String base64ImageString = encoder(imagePath);
////		System.out.println("Base64ImageString = " + base64ImageString);
//		
//		 Path path = Paths.get(imagePath);
//        byte[] bytes = Files.readAllBytes(path);
//
//        System.out.println("Check11: "+bytes);
//
//        // encode, byte[] to Base64 encoded string
//        String base64ImageString = Base64.getEncoder().encodeToString(bytes);
//        System.out.println("Check: "+base64ImageString);
////        String basecheck = Base64.getEncoder().encodeToString(bytes);
//        
//
//        // decode, Base64 encoded string to byte[]
//        byte[] decode = Base64.getDecoder().decode(base64ImageString);
//
////		byte[] Base64ImageBYTE= hexStringToByteArray(base64ImageString);
////		System.out.println("Base64ImageBYTE = " + hexStringToByteArray(base64ImageString));
////		System.out.println("Base64ImageString = " + toHex(Base64ImageBYTE));
//
//		System.out.println("=================Decoder Base64ImageString to Image!=================");
//		decoder(base64ImageString, "D:\\usr\\hii.png");
////		decoder(base64ImageString, "D:\\usr\\haaaaa.png");
//
//		System.out.println("DONE!");
//
//	}
	private static String toHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	public static String encoder(String imagePath) {
		String base64Image = "";
		File file = new File(imagePath);
		try (FileInputStream imageInFile = new FileInputStream(file)) {
			// Reading a Image file from file system
			byte imageData[] = new byte[(int) file.length()];
			imageInFile.read(imageData);
			base64Image = Base64.getEncoder().encodeToString(imageData);
		} catch (FileNotFoundException e) {
			System.out.println("Image not found" + e);
		} catch (IOException ioe) {
			System.out.println("Exception while reading the Image " + ioe);
		}
		return base64Image;
	}

	public static void decoder(String base64Image, String pathFile) {
		try (FileOutputStream imageOutFile = new FileOutputStream(pathFile)) {
			// Converting a Base64 String into Image byte array
			byte[] imageByteArray = Base64.getDecoder().decode(base64Image);
			imageOutFile.write(imageByteArray);
		} catch (FileNotFoundException e) {
			System.out.println("Image not found" + e);
		} catch (IOException ioe) {
			System.out.println("Exception while reading the Image " + ioe);
		}
	}
}
