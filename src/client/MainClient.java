package client;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import util.Certifier;
import util.Generator;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;

/**
 * @author Robert
 */
@SuppressWarnings("restriction")
public class MainClient {
    /**
     * @param args
     *            the command line arguments
     */
    public static void main(String[] args) {
	@SuppressWarnings("unused")
	Generator gen = Generator.getInstance();
	@SuppressWarnings("unused")
	Certifier certifier = Certifier.getInstance();
	try {
	    B client = new B(Generator.genP(), Generator.getAlpha());
	    Certifier.setClient(client);
	    client.Start();
	} catch (InvalidKeyException | NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException | Base64DecodingException
		| BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | IOException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}
    }
}
