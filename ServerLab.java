package uib.sec.project.chat;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.lang.String;
import java.util.Base64;

import uib.sec.project.crypto.AESCipher;
import uib.sec.project.crypto.PKCManager;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;


public class ServerLab {
	
    private static ServerSocket serverSocket ;	// socket used by server to accept connections from clients
	private static Socket clientSocket;			// socket used by server to send and receive data from client
	private static DataInputStream dataInput;	// object to read data from socket
	private static DataOutputStream dataOutput;	// object to write data into socket
	private static int serverPort;
	
	private static String ROLEMain = "Hellman"; 
	private static String ROLEClient = "Diffie"; 
	
	private static String CLOSEWORD = "QUIT"; 
	private static boolean chatOpen = true;
	
	private static Scanner scanner;
	private static String writer;
	
    public static void main(String[] args) throws Exception{
    	
		if (args.length!=1){
			  System.err.println("Default port number: 9090");
			  serverPort = 9090;
		  }
		  else {
			  serverPort = Integer.parseInt(args[0]);
		  }	

	      try {
				serverSocket = new ServerSocket(serverPort);
				log("Waiting for connections at the port "+serverPort+" ... ");
				clientSocket = serverSocket.accept();
				log("Established connection with the client ... ");
	            dataOutput = new DataOutputStream(clientSocket.getOutputStream());
	    		dataInput = new DataInputStream(clientSocket.getInputStream());
	    		
	    		
	    		//FASE 0
	    		//Enviar certificado a DIFFIE
	    		PKCManager.enviarCertificadoADiffie(dataOutput);
	    		
	    		//Recibir certificado
	    		X509Certificate certDiffie = PKCManager.recibirCertificado(dataInput);

	    		//System.out.println("DIFFIE: " + certDiffie);
	    		

	    		//FASE 1-2
	    		//Recibe la clave publica de Diffie

	    		int PULength = dataInput.readInt();
	    		byte[] PUBytes64 = new byte[PULength];
	    		dataInput.readFully(PUBytes64);
	    		
	    		//System.out.println(PUBytes64);
	    		//System.out.println("Datos Base64 recibidos: " + new String(PUBytes64, StandardCharsets.UTF_8));
	    		
	    		//Decodificar Base64 a bytes reales del la clave publica de Diffie
	    		byte[] PUDerBytes = Base64.getDecoder().decode(PUBytes64);

	    		//Extraemos parametros B,p,g
	    		X509EncodedKeySpec spec= new X509EncodedKeySpec(PUDerBytes);
	    		KeyFactory kf=KeyFactory.getInstance("DH"); //Sacamos la estructura DH
	    		DHPublicKey PUdiffieRecovered=(DHPublicKey)kf.generatePublic(spec); //Recuperamos PU de Diffie
	    		DHParameterSpec DiffieParams =PUdiffieRecovered.getParams(); //Obtiene p y g

	    		//Generar par de claves
	    		KeyPairGenerator kpgH= KeyPairGenerator.getInstance("DH");
	    		kpgH.initialize(DiffieParams);
	    		KeyPair kpH=kpgH.generateKeyPair();

	    		//Envia PU a Diffie
	    		DHPublicKey PUHellman= (DHPublicKey) kpH.getPublic();

	    		
	    		//Pasamos a B64 y enviamos data
	    		byte[]PUHellmanString_DER=PUHellman.getEncoded();
	    		//String PUHellmanString_Base64 =Base64.getEncoder().encodeToString(PUHellmanString_DER);
	    		byte[]PUHellmanArray_B64=Base64.getEncoder().encode(PUHellmanString_DER);
	    		
	    		sendBytes(PUHellmanArray_B64);
	    		
	    		//Crea clave secreta juntando su PR con la PU de DIffie y luego se la envia
	    		KeyAgreement hellmanKeyAgree=KeyAgreement.getInstance("DH");
	    		hellmanKeyAgree.init(kpH.getPrivate());
	    		hellmanKeyAgree.doPhase(PUdiffieRecovered,true); //Le damos el valor público de la otra parte a su clave privada
	    		System.out.println();
	    		byte[]hellmanSharedSecret=hellmanKeyAgree.generateSecret(); //Problema: es muy larga, hay que extraer la clave
	    		//String hellmanSharedSecret_Base64 =Base64.getEncoder().encodeToString(hellmanSharedSecret);
	    		//System.out.println(hellmanSharedSecret_Base64);
	    		
	    		//Sacar la clau secreta del AES i el byte[]de IV
	    		int aesLength= 32; //Bytes
	    		int ivlength= 16; //Bytes 
	    		byte[]aesBytes= new byte[aesLength]; //Long pendiente
	    		System.arraycopy(hellmanSharedSecret,0,aesBytes,0,aesLength);
	    		byte[]ivBytes= new byte[ivlength]; //Long pendiente
	    		System.arraycopy(hellmanSharedSecret,aesLength,ivBytes,0,ivlength);
	    		
	    		//FASE 3
	    		String ALG_MODE = "AES/CBC/PKCS5Padding";

	    		AESCipher aesClass = new AESCipher(aesBytes, ivBytes, ALG_MODE);
	    		Cipher c = aesClass.getEncryptCipher();
	    		Cipher cDecode = aesClass.getDecryptCipher();

	    		
	            Thread sender = new Thread(new Runnable() {
	                public void run() {
	                  try {
	                    while(chatOpen){
	                    	scanner = new Scanner(System.in);
	                    	writer = scanner.nextLine();
							if (!writer.equals(CLOSEWORD)) {
									sendDataEncrypted(writer,c);
							} else {
								sendDataEncrypted(writer,c);
								log("---- CHAT ENDED BY "+ROLEMain+" ----");
								chatOpen = false;
								closeAll();
								System.exit(0);
							}
	                    }
	        			closeAll();
					  } catch (IOException | IllegalBlockSizeException | BadPaddingException e) {
						  log("---- ERROR --> "+e.toString());
						  System.exit(0);
						  e.printStackTrace();
					  }
	                }
	            });  			
	            sender.start();
	            
	            Thread receiver = new Thread(new Runnable() {
	                @Override
	                public void run() {
	                  try {
	                    while(listenData(clientSocket, cDecode)){}
						closeAll();
						System.exit(0);
					  } catch (IOException | IllegalBlockSizeException | BadPaddingException e) {
						// TODO Auto-generated catch block
						  log("---- Client Socket ended ----");
						  closeAll();
						  System.exit(0);
						  e.printStackTrace();
					  }
	                }
	            });
	            receiver.start();
	            
	    }catch (IOException e){
			  log("java.net.ConnectException: Connection refused)");
			  System.exit(0);
	        }
    }
        
    public static boolean listenData(Socket socket, Cipher cDecode) throws IOException, IllegalBlockSizeException, BadPaddingException {
            byte[] dataReceived = new byte[dataInput.readInt()];
			dataInput.read(dataReceived);
		    byte [] dataDecrypted=cDecode.doFinal(dataReceived);
			textChat("( "+ROLEClient+" ) says  :   "+ new String(dataDecrypted));
			if (new String(dataReceived).equals(CLOSEWORD)) {
				log("---- CHAT ENDED BY "+ROLEClient+" ----");
				return false;
			}
			return true;		
	}
	
    
	private static void sendDataEncrypted(String datos, Cipher c) throws IOException, IllegalBlockSizeException, BadPaddingException {
		
		if(datos != null) {
			byte[] dataToSend = datos.getBytes();
			byte [] dataEncrypted=c.doFinal(dataToSend);
			dataOutput.writeInt(dataEncrypted.length);
			dataOutput.write(dataEncrypted);
			dataOutput.flush();
		}
	}
	
	private static void sendBytes(byte[] dataToSend) throws IOException, IllegalBlockSizeException, BadPaddingException {
		if(dataToSend != null) {
			dataOutput.writeInt(dataToSend.length);
			dataOutput.write(dataToSend);
			dataOutput.flush();
		}
	}
	
	private static void closeAll() {
		try {
			dataOutput.close();
			dataInput.close();
			clientSocket.close();
			serverSocket.close();
		} catch (IOException ex) {
			log("Exception Chat "+ROLEMain+".closeAll --> "+ex);
		}
	}
	
	private static void log(String logText) {
		System.out.println(ROLEMain+" LOG : " + logText);
	}

	
	private static void textChat(String logText) {
		System.out.println(logText);
	}
  }
