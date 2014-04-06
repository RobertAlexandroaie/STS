package server;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import util.Certifier;
import util.Constants;
import util.Generator;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

/**
 * @author Robert
 */
@SuppressWarnings("restriction")
public class A {

    public BigInteger p, alpha, Key;
    private BigInteger xB;

    private PublicKey pkA;
    private PublicKey pkB;
    private PrivateKey sk;

    private int idB = 256;
    private int idA = 534;

    public A(BigInteger p, BigInteger alpha) {
	this.p = p;
	this.alpha = alpha;
    }

    public void genKeyPair() {
	try {
	    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
	    keyGen.initialize(512, new SecureRandom());
	    KeyPair keyPair = keyGen.generateKeyPair();
	    this.pkA = keyPair.getPublic();
	    this.sk = keyPair.getPrivate();

	} catch (NoSuchAlgorithmException e) {
	    System.out.println(e.toString());
	} catch (NoSuchProviderException ex) {
	    Logger.getLogger(A.class.getName()).log(Level.SEVERE, null, ex);
	}
    }

    public void saveKpA(PublicKey keyPair) throws IOException {
	X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pkA.getEncoded());
	FileOutputStream fos = new FileOutputStream("pubA.key");
	fos.write(x509EncodedKeySpec.getEncoded());
	fos.close();
    }

    public byte[] sign(String alphaY, String alphaX) {
	byte[] sig = null;

	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	Signature signature;
	String message;

	try {
	    signature = Signature.getInstance("SHA1withRSA", "BC");
	    signature.initSign(this.sk, new SecureRandom());

	    message = alphaY + "|" + alphaX;

	    byte[] m = message.getBytes();

	    signature.update(m);
	    sig = signature.sign();
	} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException ex) {
	    Logger.getLogger(A.class.getName()).log(Level.SEVERE, null, ex);
	}

	return sig;

    }

    public PublicKey readKpB() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
	File filePublicKey = new File("pubB.key");
	FileInputStream fis = new FileInputStream("pubB.key");
	byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
	fis.read(encodedPublicKey);
	fis.close();

	KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
	X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
	PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

	return publicKey;
    }

    public byte[] gen3DesKey() {
	String msg = Integer.toString(idB) + this.Key + Integer.toString(idA);
	byte[] key = new byte[16];
	try {
	    MessageDigest md = MessageDigest.getInstance("SHA-256");
	    md.update(msg.getBytes());
	    byte byteData[] = md.digest();

	    int j = 0;
	    for (int i = byteData.length - 16; i < byteData.length; i++) {
		key[j] = byteData[i];
		j++;
	    }
	} catch (NoSuchAlgorithmException ex) {
	    Logger.getLogger(A.class.getName()).log(Level.SEVERE, null, ex);
	}
	return key;
    }

    public String decript3DES(byte[] encryptionBytes, byte[] byteKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
	    NoSuchAlgorithmException, NoSuchPaddingException {

	Key key = new SecretKeySpec(byteKey, "DESede");
	Cipher cipher = Cipher.getInstance("DESede");
	cipher.init(Cipher.DECRYPT_MODE, key);
	byte[] recoveredBytes = cipher.doFinal(encryptionBytes);
	String recovered = new String(recoveredBytes);
	return recovered;
    }

    public void Start() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, Base64DecodingException,
	    InvalidKeyException, InvalidKeyException, BadPaddingException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {

	String sendMessage;
	String receivedMessage;

	ServerSocket serverSocket = new ServerSocket(Constants.SERVER_PORT);
	System.out.println("[server]Awaiting client");
	Socket clientSocket = serverSocket.accept();
	BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
	DataOutputStream writer = new DataOutputStream(clientSocket.getOutputStream());
	// I
	p = Generator.getP();
	alpha = Generator.getAlpha();
	System.out.println("Alpha: \n" + alpha);

	this.genKeyPair();
	saveKpA(this.pkA);
	this.pkB = readKpB();

	sendMessage = p + " " + alpha + "\n";
	writer.writeBytes(sendMessage);

	Random random = new SecureRandom();
	xB = BigInteger.probablePrime(512, random);

	BigInteger yA = alpha.modPow(xB, p);
	sendMessage = "";
	sendMessage = yA + "\n";
	String yAString = yA.toString();

	System.out.println("\n[server]gen xA:\n" + xB + "\n, yA:\n" + yA);
	writer.writeBytes(sendMessage);
	System.out.println("[server][send] yA=alpha.modPow(xa, p): " + sendMessage);

	receivedMessage = reader.readLine();
	System.out.println("\n[server][recieved] yB=alpha.modPow(xb, p) \n " + receivedMessage);
	String yBString = receivedMessage;

	String sgn = "";
	receivedMessage = reader.readLine();

	while (receivedMessage.compareTo("finished") != 0) {
	    sgn += "\n" + receivedMessage;
	    receivedMessage = reader.readLine();
	}

	System.out.println("\n[server][recieved] sig(alfa^y,alfa^x)\n" + sgn);

	if (Certifier.verifySig(yBString + "|" + yAString, Base64.decode(sgn.getBytes()), pkB)) {
	    System.out.println("\n[server]Semnatura Verificata!\n");

	    sgn = Base64.encode(this.sign(yAString, yBString), Base64.BASE64DEFAULTLENGTH);
	    writer.writeBytes(sgn + "\nfinished\n");
	    System.out.println("\n[server][sent]sig(alfa^x|alfa^y)\n" + sgn);

	    BigInteger yB = new BigInteger(yBString);
	    Key = yB.modPow(this.xB, p);
	    System.out.println("\n[server]Key :" + Key);

	    // II
	    receivedMessage = reader.readLine();
	    System.out.println("\n[server][recieved]Cripted message :\n" + receivedMessage);
	    com.sun.org.apache.xml.internal.security.Init.init();
	    byte[] encrypted = Base64.decode(receivedMessage.getBytes());
	    System.out.println("\n[server]Decripted: " + this.decript3DES(encrypted, this.gen3DesKey()));

	    byte[] DES3Key = this.gen3DesKey();
	    System.out.println("[server]3DES key:");
	    System.out.write(DES3Key);
	} else {
	    System.out.println("[server]Invalid sig");
	}
	serverSocket.close();
    }
}
