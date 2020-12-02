import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.SecretKeySpec;



public class ServerReceiver {
	private static final int PORT = 8080;

	public static void main(String[] args) throws Exception {
		System.out.println("The server is running.");
		String pid = new File("/proc/self").getCanonicalFile().getName();
		System.out.println("Process ID of currently running server process : " + pid);
		ServerSocket listener = new ServerSocket(PORT);
		try {
			while (true) {
				new Handler(listener.accept()).start();
			}
		} finally {
			listener.close();
		}
	}

	private static class Handler extends Thread {
		private Socket socket;
		private InputStream in;
		private OutputStream out;

		private void sendPublicKey() throws IOException {
			StringBuilder messageHeader = new StringBuilder();
			messageHeader.append("PUBLIC KEY\n");
			File publicKeyFile = new File("public.der");
			messageHeader.append(publicKeyFile.length() + "\n\n");
			out.write(messageHeader.toString().getBytes("ASCII"));
			out.write(Files.readAllBytes(publicKeyFile.toPath()));
			out.flush();
		}

		private void sendErrorMessage(String msg) {
			try {
				msg = "ERROR\n" + msg + "\n\n";
				out.write(msg.getBytes("ASCII"));
			} catch (IOException e) {
				System.out.println("Failed to send an error message to client.");
				System.exit(1);
			}
		}

		private byte[] readAndDecryptAesKey(byte[] privateKeyFile) throws GeneralSecurityException, IOException {
			
            // read the encrypted AES key from the socket
            byte[] pid = new byte[5];
			byte[] encryptedAesKey = new byte[ProtocolUtilities.KEY_SIZE_AES * 2];
			in.read(encryptedAesKey);
			String aes = new String(encryptedAesKey);

			System.out.println("\nEncrypted AES key : "+aes);
			
            in.read(pid);
            String x = new String(pid);
            // put the private RSA key in the appropriate data structure
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyFile);
			PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
            System.out.println("\nPrivate RSA key : "+privateKey.toString());
            
			// Decipher the AES key using the private RSA key
			Cipher pkCipher = Cipher.getInstance("RSA");
			pkCipher.init(Cipher.DECRYPT_MODE, privateKey);
			CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(encryptedAesKey), pkCipher);
			byte[] aesKey = new byte[ProtocolUtilities.KEY_SIZE_AES / 8];
            System.out.println("\nAES key : "+aesKey);
			
            cipherInputStream.read(aesKey);
            System.out.println("\nPID of the Client : " + x);
			cipherInputStream.close();
            
            /*
            String FILEPATH = "AES_encrypted.txt"; 
            File file = new File(FILEPATH); 
            try { 
  
            // Initialize a pointer in file using OutputStream 
            OutputStream os = new FileOutputStream(file); 
  
            // Starts writing the bytes in it 
            os.write(encryptedAesKey);
            os.write(aesKey);    
            // Close the file 
            os.close(); 
            } 
  
        catch (Exception e) { 
            System.out.println("Exception: " + e); 
        } */
            
			return aesKey;
		}
		
		private String scanLineFromCipherStream(CipherInputStream cstream) throws IOException {
			StringBuilder line = new StringBuilder();
			char c;
			while ((c = (char) cstream.read()) != '\n') {
				line.append(c);
			}
			return line.toString();
		}
		
		private File receiveFile(byte[] aesKey) throws GeneralSecurityException, IOException {
			Cipher aesCipher = Cipher.getInstance("AES");
			SecretKeySpec aeskeySpec = new SecretKeySpec(aesKey, "AES");
			aesCipher.init(Cipher.DECRYPT_MODE, aeskeySpec);
			CipherInputStream cipherInputStream = new CipherInputStream(in, aesCipher);
			String fileName = scanLineFromCipherStream(cipherInputStream);
			String fileSize = scanLineFromCipherStream(cipherInputStream);
			File receivedFile = new File(fileName.toString());
			FileOutputStream foStream = new FileOutputStream(receivedFile);
			ProtocolUtilities.sendBytes(cipherInputStream, foStream, Long.parseLong(fileSize));
			foStream.flush();
			foStream.close();
			return receivedFile;
		}

		public Handler(Socket socket) {
			this.socket = socket;
		}

		public void run() {
			String command;
			try {
				in = new BufferedInputStream(socket.getInputStream());
				out = new BufferedOutputStream(socket.getOutputStream());
				ArrayList<String> headerParts = ProtocolUtilities.consumeAndBreakHeader(in);
				command = headerParts.get(0);
			} catch (IOException e) {
				e.printStackTrace();
				System.err.println("Connection to client dropped.");
				return;
			} catch (NullPointerException e) {
				System.err.println("Unable to read command from client");
				return;
			}
			switch (command) {
			case "GET PUBLIC KEY":
				try {
					sendPublicKey();
					System.out.println("\nSent public key!");
				} catch (IOException e) {
					System.err.println("\nConnection to client dropped. Failed to send public key.");
				}
				break;
			case "FILE TRANSFER":
				byte[] privateRsaKey;
				try {
					privateRsaKey = Files.readAllBytes(new File("private.der").toPath());
				} catch (IOException e) {
					sendErrorMessage("SERVER ERROR");
					System.err.println("Server failed to open private key file.");
					return;
				}
				try {
					byte[] aesKey = readAndDecryptAesKey(privateRsaKey);
					File file = receiveFile(aesKey);
					System.out.println("\nReceived File");
					System.out.println("\nName: " + file.getName());
					System.out.println("\nSize:" + file.length() + " bytes");
					out.write("\nSUCCESS\nsuccessful transmission\n\n".getBytes("ASCII"));
					out.flush();
					socket.close();
				} catch (GeneralSecurityException e) {
					sendErrorMessage("Failed to decrypt AES key and/or file content.");
					System.err.println("Server failed to decrypt AES key and/or file content.");
					return;
				} catch (IOException e) {
					e.printStackTrace();
					System.err.println("Connection to client dropped.");
					return;
				}
				break;
			default:
				sendErrorMessage("INVALID COMMAND");
				System.out.println("Invalid command detected: " + command);
			}
		}
	}
}