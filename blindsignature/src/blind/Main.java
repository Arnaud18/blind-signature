package blind;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Main {
	
	public static void main(String []args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, 
	ClassNotFoundException{
		String publicKeyFileName="publicKeyFile.key";
		String privateKeyFileName="privateKeyFile.key";
	System.out.println("Saisissez le message à signer: ");
	BufferedReader bf=new BufferedReader(new InputStreamReader(System.in));
	byte[]message=bf.readLine().getBytes();
BlindSignature sign=new BlindSignature(publicKeyFileName, privateKeyFileName, message);
sign.blindAndVerify();
}
}
