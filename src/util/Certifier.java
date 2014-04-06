/**
 * 
 */
package util;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;

import server.A;
import client.B;

/**
 * @author Robert
 */
public class Certifier {
    @SuppressWarnings("unused")
    private static A server;
    @SuppressWarnings("unused")
    private static B client;
    private static Certifier instance = null;

    private Certifier() {
    }

    public static Certifier getInstance() {
	if (instance == null) {
	    instance = new Certifier();
	}
	return instance;
    }

    public static void setClient(B client) {
	Certifier.client = client;
    }

    public static void setServer(A server) {
	Certifier.server = server;
    }

    public static boolean verifySig(String mesaj, byte[] signatura, PublicKey pK) {

	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	boolean ok = false;
	Signature signature;
	try {
	    signature = Signature.getInstance("SHA1withRSA", "BC");
	    signature.initVerify(pK);
	    signature.update(mesaj.getBytes());
	    ok = signature.verify(signatura);
	} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException ex) {
	    Logger.getLogger(B.class.getName()).log(Level.SEVERE, null, ex);
	}
	return ok;
    }

}
