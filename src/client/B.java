/**
 * 
 */
package client;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
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
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import util.Certifier;
import util.Constants;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

/**
 * @author Robert
 */
@SuppressWarnings("restriction")
public class B {
    private BigInteger p, alpha, Key;
    private BigInteger xB;

    private PrivateKey sk;
    private PublicKey pkA;
    private PublicKey pkB;

    private int idB = 256;
    private int idA = 534;

    public B(BigInteger p, BigInteger alpha) {
	this.p = p;
	this.alpha = alpha;
    }

    public byte[] sig(String alphaY, String alphaX) {
	byte[] sig = null;

	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	Signature signature;
	String message;

	try {
	    signature = Signature.getInstance("SHA1withRSA", "BC");
	    signature.initSign(this.sk, new SecureRandom());

	    message = alphaY + "|" + alphaX;// this.data.a.modPow(this.y,
					    // this.data.p).toString();

	    byte[] m = message.getBytes();

	    signature.update(m);
	    sig = signature.sign();
	} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException ex) {
	    Logger.getLogger(B.class.getName()).log(Level.SEVERE, null, ex);
	}

	return sig;

    }

    public void SaveKeyPair(PublicKey keyPair) throws IOException {
	// Store Public Key.
	X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pkB.getEncoded());
	FileOutputStream fos = new FileOutputStream("pubB.key");
	fos.write(x509EncodedKeySpec.getEncoded());
	fos.close();
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
		key[j++] = byteData[i];
	    }
	} catch (NoSuchAlgorithmException ex) {
	    Logger.getLogger(B.class.getName()).log(Level.SEVERE, null, ex);
	}

	return key;
    }

    public byte[] cript3DES(String input, byte[] byteKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
	    NoSuchAlgorithmException, NoSuchPaddingException {
	Cipher cipher;
	Key k = new SecretKeySpec(byteKey, "DESede");
	cipher = Cipher.getInstance("DESede");
	cipher.init(Cipher.ENCRYPT_MODE, k);
	byte[] inputBytes = input.getBytes();
	return cipher.doFinal(inputBytes);
    }

    public PublicKey LoadKeyPair() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
	File filePublicKey = new File("pubA.key");
	FileInputStream fis = new FileInputStream("pubA.key");
	byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
	fis.read(encodedPublicKey);
	fis.close();

	KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
	X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
	PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

	return publicKey;
    }

    public void generateKeys() {
	try {
	    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
	    keyGen.initialize(512);
	    KeyPair keyPair = keyGen.generateKeyPair();
	    this.pkB = keyPair.getPublic();
	    this.sk = keyPair.getPrivate();

	} catch (NoSuchAlgorithmException e) {
	    System.out.println(e.toString());
	} catch (NoSuchProviderException ex) {
	    Logger.getLogger(B.class.getName()).log(Level.SEVERE, null, ex);
	}
    }

    public void Start() throws UnknownHostException, IOException, NoSuchProviderException, NoSuchAlgorithmException, NoSuchAlgorithmException,
	    InvalidKeySpecException, Base64DecodingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
	    NoSuchPaddingException {
	String message;
	try (Socket clientSocket = new Socket(Constants.IP, Constants.SERVER_PORT)) {
	    DataOutputStream writer = new DataOutputStream(clientSocket.getOutputStream());
	    BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
	    this.generateKeys();
	    SaveKeyPair(this.pkB);

	    // I
	    message = reader.readLine();
	    this.pkA = LoadKeyPair();
	    StringTokenizer st = new StringTokenizer(message);
	    String pString = st.nextToken();
	    String alphaString = st.nextToken();

	    p = new BigInteger(pString);
	    alpha = new BigInteger(alphaString);

	    System.out.println("[client][recieved]Alpha: \n" + alpha);

	    message = reader.readLine();

	    String alphaXString = message;

	    Random random = new SecureRandom();
	    xB = BigInteger.probablePrime(512, random);

	    BigInteger yB = alpha.modPow(xB, p);
	    message = "";
	    message = yB + "\n";
	    String yBString = yB.toString();
	    writer.writeBytes(message);

	    String sgn = Base64.encode(this.sig(yBString, alphaXString), Base64.BASE64DEFAULTLENGTH);
	    writer.writeBytes(sgn + "\nfinished\n");

	    sgn = "";
	    message = reader.readLine();

	    while (message.compareTo("finished") != 0) {
		sgn += "\n" + message;
		message = reader.readLine();

	    }

	    String msg1 = alphaXString + "|" + yBString;

	    if (Certifier.verifySig(msg1, Base64.decode(sgn.getBytes()), pkA)) {
		System.out.println("\n[client]Sig ok!\n");

		BigInteger alphaX = new BigInteger(alphaXString);
		Key = alphaX.modPow(this.xB, p);
		System.out.println("[client]Key :" + Key + "\n");

		// II

		String msg = Base64.encode(this.cript3DES("Mesaj super secret", gen3DesKey()));
		System.out.println("[client]Byte key:");
		System.out.write(gen3DesKey());

		writer.writeBytes(msg + "\n");
		System.out.println("\n[client][sent]Cripted msg:\n" + msg);
		clientSocket.close();
	    } else {
		System.out.println("[client]Invalid sig");
		clientSocket.close();
	    }
	}
    }
}
