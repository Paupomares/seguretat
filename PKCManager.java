package uib.sec.project.crypto;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;

public class PKCManager {



	public static void enviarCertificadoADiffie(DataOutputStream dataOutput) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");

		String pass = "4I9c6j@NiOaNEq&0K6";
		char[] password = pass.toCharArray();

		keyStore.load(new FileInputStream("C:\\Users\\Pau\\Downloads\\certificate_s_mime2.p12"), password);

		Enumeration<String> aliases = keyStore.aliases();
		String alias = aliases.nextElement();

		X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
		byte[] certString_DER = cert.getEncoded();
		byte[] certArray_B64 = Base64.getEncoder().encode(certString_DER);

		dataOutput.writeInt(certArray_B64.length);
		dataOutput.write(certArray_B64);
		dataOutput.flush();
		
		// Envía la firma después del certificado
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
		byte[] firma = firmarCertificado(cert, privateKey);

		
		dataOutput.writeInt(firma.length);
		dataOutput.write(firma);
		dataOutput.flush();
	}

	public static void enviarCertificadoAHellman(DataOutputStream dataOutput) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");

		String pass = "o8&u17bCxL=s8Ou6kU";
		char[] password = pass.toCharArray();

		keyStore.load(new FileInputStream("C:\\Users\\Pau\\Downloads\\certificate_s_mime.p12"), password);

		Enumeration<String> aliases = keyStore.aliases();
		String alias = aliases.nextElement();

		X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
		byte[] certString_DER = cert.getEncoded();
		byte[] certArray_B64 = Base64.getEncoder().encode(certString_DER);

		dataOutput.writeInt(certArray_B64.length);
		dataOutput.write(certArray_B64);
		dataOutput.flush();
		
		// Envía la firma después del certificado
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
		byte[] firma = firmarCertificado(cert, privateKey);


		dataOutput.writeInt(firma.length);
		dataOutput.write(firma);
		dataOutput.flush();
	}
	
	public static X509Certificate recibirCertificado(DataInputStream dataInput) throws Exception {
		int certLength = dataInput.readInt();
		byte[] certBytes64 = new byte[certLength];
		dataInput.readFully(certBytes64);

		byte[] certDerBytes = Base64.getDecoder().decode(certBytes64);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		InputStream in = new ByteArrayInputStream(certDerBytes);
		X509Certificate cert=(X509Certificate) certFactory.generateCertificate(in);
		
		// Leer la firma
	    int firmaLength = dataInput.readInt();
	    byte[] firma = new byte[firmaLength];
	    dataInput.readFully(firma);

	    boolean firmaValida = verificarCertificado(cert, firma);
	    if (!firmaValida) {
	        throw new SecurityException("Firma del certificado no válida");
	    } else if (firmaValida) {
	    	System.out.println("Firma del certificado valida");	    }

	    return cert;
	}
	
	public static byte[] firmarCertificado(X509Certificate cert, PrivateKey privateKey) throws Exception {
	    Signature signature = Signature.getInstance("SHA256withRSA");
	    signature.initSign(privateKey);
	    signature.update(cert.getEncoded());
	    return signature.sign(); // devuelve la firma en bytes
	}
	
	public static boolean verificarCertificado(X509Certificate cert, byte[] firma) throws Exception {
	    Signature signature = Signature.getInstance("SHA256withRSA");
	    signature.initVerify(cert.getPublicKey());
	    signature.update(cert.getEncoded());
	    return signature.verify(firma);
	}


}

