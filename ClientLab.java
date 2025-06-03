package uib.sec.project.chat;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Scanner;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

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

public class ClientLab {
	
	private static Socket socketClient;			// socket used by client to send and recieve data from server
	private static DataInputStream dataInput;	// object to read data from socket
	private static DataOutputStream dataOutput;	// object to write data into socket
	private static int serverPort;
	private static InetAddress serverIP;
	
	private static String ROLEMain = "Diffie"; 
	private static String ROLEClient = "Hellman"; 
	
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
			serverIP = InetAddress.getLocalHost();
		} catch (UnknownHostException e1) {
			System.exit(0);
		}
        try {
        	log("Connect to IP --> "+serverIP+"  Port --> "+serverPort);
        	socketClient = new Socket(serverIP,serverPort);
            dataOutput = new DataOutputStream(socketClient.getOutputStream());
    		dataInput = new DataInputStream(socketClient.getInputStream());
    		
    		//FASE 0
    		//Enviar certificado a HELLMAN
    		PKCManager.enviarCertificadoAHellman(dataOutput);
    		
    		//Recibir certificado
    		X509Certificate certHellman = PKCManager.recibirCertificado(dataInput);
    		//System.out.println("HELLMAN: " + certHellman);
    		
    		
    		//FASE 1-2
    		//Generamos las claves de Diffie
    		KeyPairGenerator kpg= KeyPairGenerator.getInstance("DH");
    		kpg.initialize(2048);
    		KeyPair kp=kpg.generateKeyPair();

    		//Sacar claves
    		DHPublicKey PU= (DHPublicKey) kp.getPublic();
    		DHPrivateKey PR= (DHPrivateKey) kp.getPrivate();
    		byte[]PU_DER = PU.getEncoded();
    		
    		
    		//Pasamos a B64 y enviamos la clave
    		//System.out.println("DER:"+PU_DER);
    		//System.out.println("byte[]:"+Arrays.toString(PU_DER));
    		String keyString_Base64 =Base64.getEncoder().encodeToString(PU_DER);
    		//System.out.println("BASE64:"+keyString_Base64);
    		byte[]PU_B64=Base64.getEncoder().encode(PU_DER);
    		sendBytes(PU_B64);
    		
    		//Decodificar la PU de Hellman
    		int PUHellmanLength = dataInput.readInt();
    		byte[] PUHellmanBytes64 = new byte[PUHellmanLength];
    		dataInput.readFully(PUHellmanBytes64);
    		
    		//Decodificar Base64 a bytes reales 
    		byte[] PUHellmanDerBytes = Base64.getDecoder().decode(PUHellmanBytes64);
    		//Extraer clave publica de Hellman
    		X509EncodedKeySpec spec= new X509EncodedKeySpec(PUHellmanDerBytes);
    		KeyFactory kf=KeyFactory.getInstance("DH"); //Sacamos la estructura DH
    		DHPublicKey PUHellmanRecovered=(DHPublicKey)kf.generatePublic(spec); //Recuperamos PU de Hellman
    		
    		
    		
    		//Crea clave secreta juntando su PR con la PU de Hellamn y luego se la envia
    		KeyAgreement diffieKeyAgree=KeyAgreement.getInstance("DH");
    		diffieKeyAgree.init(kp.getPrivate());
    		diffieKeyAgree.doPhase(PUHellmanRecovered,true); //Le damos el valor público de la otra parte a su clave privada
    		byte[]diffieSharedSecret=diffieKeyAgree.generateSecret(); //Problema: es muy larga, hay que extraer la clave
    		String diffieSharedSecret_Base64 =Base64.getEncoder().encodeToString(diffieSharedSecret);
    		//System.out.println(diffieSharedSecret_Base64);
    		
    		//Sacar la clau secreta del AES i el byte[]de IV
    		int aesLength= 32; //Bytes
    		int ivlength= 16; //Bytes 
    		byte[]aesBytes= new byte[aesLength]; //Long pendiente
    		System.arraycopy(diffieSharedSecret,0,aesBytes,0,aesLength);
    		byte[]ivBytes= new byte[ivlength]; //Long pendiente
    		System.arraycopy(diffieSharedSecret,aesLength,ivBytes,0,ivlength);
    		
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
						// TODO Auto-generated catch block
					  log("ERROR --> "+e.toString());
					  System.exit(0);
					//e.printStackTrace();
				  }
                }
            });
            			
            sender.start();
            Thread receiver = new Thread(new Runnable() {
                @Override
                public void run() {
                  try {
                    while(listenData(socketClient, cDecode)){}
					log("Server out of service");
					closeAll();
					System.exit(0);
				  } catch (IOException | IllegalBlockSizeException | BadPaddingException e) {
					// TODO Auto-generated catch block
					  log("ERROR --> "+e.toString());
					  closeAll();
					  System.exit(0);
				  }
                }
            });
            receiver.start();
    }catch (IOException e){
    	  log("ERROR --> "+e.toString());
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
	
	
	private static void sendData(String datos) throws IOException {
			if(datos != null) {
				byte[] dataToSend = datos.getBytes();
				dataOutput.writeInt(dataToSend.length);
				dataOutput.write(dataToSend);
				dataOutput.flush();
			}
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
	
	private static void sendBytes(byte[] dataToSend) throws IOException {
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
			socketClient.close();
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
