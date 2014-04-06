/**
 * 
 */
package server;

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
public class MainServer {

    /**
     * @param args
     */
    public static void main(String[] args) {
	// TODO Auto-generated method stub
	@SuppressWarnings("unused")
	Generator gen = Generator.getInstance();
	@SuppressWarnings("unused")
	Certifier certifier = Certifier.getInstance();
	try {
	    A server = new A(Generator.getP(), Generator.getAlpha());
	    Certifier.setServer(server);
	    server.Start();
	} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | Base64DecodingException
		| BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | IOException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}
    }

}
