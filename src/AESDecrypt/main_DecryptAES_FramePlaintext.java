package AESDecrypt;

import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

public class main_DecryptAES_FramePlaintext {

	public final static int port = 9999;
	public final static String localhost = "127.0.0.1";
	public static byte[] text;
	public static FileWriter myWriter;

	/* Transform a byte array in an hexadecimal string */
	private static String toHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	/* Transform a byte array in an hexadecimal string */
	private static String toHex(byte data) {
		StringBuilder sb = new StringBuilder();
		sb.append(String.format("%02x", data & 0xff));

		return sb.toString();
	}

	/* Convert long to byte array */
	private static byte[] longToByteArray(long value) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(value);
		return buffer.array();

	}

	/* Convert a string representation in its hexadecimal string */
	private static String toHex(String arg) {
		return String.format("%02x", new BigInteger(1, arg.getBytes()));
	}

	/*
	 * Transform an hexadecimal string in byte array (It works if the string only
	 * contains the hexadecimal characters)
	 */
	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	/* Concatenation of two byte arrays */
	private static byte[] concatByteArrays(byte[] a, byte b) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try {
			outputStream.write(a);
			outputStream.write(b);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] concatResult = outputStream.toByteArray();
		return concatResult;
	}

	private static byte[] concatByteArrays(byte[] a, byte[] b) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try {
			outputStream.write(a);
			outputStream.write(b);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] concatResult = outputStream.toByteArray();
		return concatResult;
	}

	public static String DecryptResource(byte[] ciphertext) {
		byte[] plaintext = new byte[ciphertext.length];
		String kzz = "0f1571c947d9e8590cb7add6af7f6798";
		byte[] kz = hexStringToByteArray(kzz);

		AESEngineCBCmode newAES = new AESEngineCBCmode(kz);
		newAES.Decrypt(ciphertext, plaintext);
		return toHex(plaintext);
	}

	/**************************
	 * decrypt with plaintext
	 *******************************/
//	public static void main(String[] args) throws IOException {
//		HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
//		System.out.println("httpServer start at port: " + port);
//		server.createContext("/DecryptAES", new MyHandler());
//		server.setExecutor(null); // creates a default executor
//		server.start();
//	}
//
//
//	static class MyHandler implements HttpHandler {
//		public void handle(HttpExchange httpExchange) throws IOException {
//			System.out.println("Method: " + httpExchange.getRequestMethod());
//
//			if ("GET".equals(httpExchange.getRequestMethod())) {
//
//				// requestParamValue = handleGetRequest(httpExchange);
//
//			} else if ("POST".equals(httpExchange.getRequestMethod())) {
//				handlePostRequest(httpExchange);
//			}
//			// handleResponse(httpExchange, requestParamValue);
//		}

//		private void handlePostRequest(HttpExchange httpExchange) throws IOException {
//			// TODO Auto-generated method stub
//			System.out.println("Running in handle Post ");
//			// String address = httpExchange.getRemoteAddress().toString();
//
//			StringBuilder sb = new StringBuilder();
//			InputStream ios = httpExchange.getRequestBody();
//			int i;
//			while ((i = ios.read()) != -1) {
//				sb.append((char) i);
//			}
//			String jsonStr = sb.toString();
//
//			Object obj = JSONValue.parse(jsonStr);
//			JSONObject jsonObject = (JSONObject) obj;
//			String Ciphertext = (String) jsonObject.get("ciphertext");
//			System.out.println("ciphertext: "+Ciphertext);
//			byte[] ciphertext = hexStringToByteArray(Ciphertext);
//			
//			System.out.println("\nplaintext: "+DecryptResource(ciphertext));
//			
//			String htmlResponse = "OK";
//			httpExchange.sendResponseHeaders(200, htmlResponse.length());
//			OutputStream os = httpExchange.getResponseBody();
//			os.write(htmlResponse.getBytes());
//			os.close();
//		}
//	}
	
	
	
	

	/**************** transfer frame plaintext with number then encrypt  **************/
	public static void main(String[] args) throws IOException {
		HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
		System.out.println("httpServer start at port: " + port);
		server.createContext("/DecryptAES", new MyHandler());
		server.setExecutor(null); // creates a default executor
		server.start();
	}

	static class MyHandler implements HttpHandler {
		public void handle(HttpExchange httpExchange) throws IOException {
			System.out.println("Method: " + httpExchange.getRequestMethod());

			if ("GET".equals(httpExchange.getRequestMethod())) {

				// requestParamValue = handleGetRequest(httpExchange);

			} else if ("POST".equals(httpExchange.getRequestMethod())) {
				handlePostRequest(httpExchange);
			}
			// handleResponse(httpExchange, requestParamValue);
		}

		private void handlePostRequest(HttpExchange httpExchange) throws IOException {
			// TODO Auto-generated method stub
			System.out.println("Running in handle Post ");
			// String address = httpExchange.getRemoteAddress().toString();

			StringBuilder sb = new StringBuilder();
			InputStream ios = httpExchange.getRequestBody();
			int i;
			while ((i = ios.read()) != -1) {
				sb.append((char) i);
			}
			String jsonStr = sb.toString();

			Object obj = JSONValue.parse(jsonStr);
			JSONObject jsonObject = (JSONObject) obj;
			String end = (String) jsonObject.get("end");
			String Ciphertext = (String) jsonObject.get("ciphertext");
			System.out.println("ciphertext: " + Ciphertext);
			byte[] cipher = hexStringToByteArray(Ciphertext);

			byte[] ciphert = new byte[cipher.length - 1];
			System.arraycopy(cipher, 0, ciphert, 0, cipher.length - 1);

			if (cipher[cipher.length - 1] == (byte) 0) {
				text = ciphert;
			} else {
				text = concatByteArrays(text, ciphert);
			}

			System.out.println(toHex(text));
			if (end.equals("endPlaintext")) {
				System.out.println("----------");
				System.out.println(toHex(text));

				// write file to D:...
				try {
					System.out.println("plaintext: "+DecryptResource(text));
					FileWriter myWriter = new FileWriter("D:\\eclipse project\\AES\\consoleView\\console.txt");
					myWriter.write(DecryptResource(text));
					myWriter.close();
				} catch (IOException e) {
					System.out.println("An error occurred.");
					e.printStackTrace();
				}
				String htmlResponse = toHex(cipher[cipher.length - 1]);
				httpExchange.sendResponseHeaders(200, htmlResponse.length());
				System.out.println("htmlResponse: " + htmlResponse);
				OutputStream os = httpExchange.getResponseBody();
				os.write(htmlResponse.getBytes());
				os.close();
			}
			String htmlResponse = toHex(cipher[cipher.length - 1]);
			httpExchange.sendResponseHeaders(200, htmlResponse.length());
			System.out.println("htmlResponse: " + htmlResponse);
			OutputStream os = httpExchange.getResponseBody();
			os.write(htmlResponse.getBytes());
			

		}
	}

}
