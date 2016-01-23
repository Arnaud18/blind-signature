package blind;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import org.bouncycastle.crypto.engines.RSABlindingEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSABlindingFactorGenerator;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;

public class BlindSignature {
   String privateKeyFile=null;
   String publicKeyFile=null;
   byte[]message=null;
  public  BlindSignature(String publicKeyFile,String privateKeyFile, byte[] message){
	this.publicKeyFile=publicKeyFile; 
	this.privateKeyFile=privateKeyFile;
	this.message=message;
   }
	public void blindAndVerify() throws NoSuchAlgorithmException, 
	                                    InvalidKeySpecException, IOException, ClassNotFoundException{
		//Génération d'une clé paire de clés RSA de 2048 bits
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();	
		PublicKey publicKey = kp.getPublic();
		PrivateKey privateKey = kp.getPrivate();
		
		//Stockage des 2 clés dans des fichiers
		//On va juste stocker le modelus et l'exponent
		KeyFactory keyFact = KeyFactory.getInstance("RSA");		
		RSAPublicKeySpec RSAKeySpec = (RSAPublicKeySpec) keyFact.getKeySpec(publicKey, RSAPublicKeySpec.class);
		BigInteger publicModelus= RSAKeySpec.getModulus();
		BigInteger publicExponent = RSAKeySpec.getPublicExponent();
		
		FileOutputStream fp = new FileOutputStream(publicKeyFile);		
		ObjectOutputStream filePublique = new ObjectOutputStream(fp);
		filePublique.writeObject(publicModelus);
		filePublique.writeObject(publicExponent);
		
		RSAPrivateKeySpec RSAPrivKeySpec = (RSAPrivateKeySpec) keyFact.getKeySpec(privateKey, RSAPrivateKeySpec.class);
		BigInteger privateModelus = RSAPrivKeySpec.getModulus();			
		BigInteger privateExponent = RSAPrivKeySpec.getPrivateExponent();	
		
		FileOutputStream fosPriv = new FileOutputStream(privateKeyFile);	
		ObjectOutputStream oosPriv = new ObjectOutputStream(fosPriv);
		oosPriv.writeObject(privateModelus);
		oosPriv.writeObject(privateExponent);
		
		// Rechargement de clés à partir des fichiers
		FileInputStream fiPublique = new FileInputStream(publicKeyFile);
	    ObjectInputStream oisPub = new ObjectInputStream(fiPublique);
	       
	    BigInteger publicModulus2 = (BigInteger) oisPub.readObject();
	    BigInteger publicExponent2 = (BigInteger) oisPub.readObject();
	    RSAPublicKeySpec rsaPubKeyspec =  new RSAPublicKeySpec(publicModulus2, publicExponent2);
	    
	    PublicKey publicKey2 = keyFact.generatePublic(rsaPubKeyspec);
	   
		//rétrouver la clé privée
		FileInputStream fisPriv = new FileInputStream(privateKeyFile); 
		ObjectInputStream oisPriv = new ObjectInputStream(fisPriv);
		
		BigInteger privateModulus2 = (BigInteger) oisPriv.readObject();
		BigInteger privateExponent2 = (BigInteger) oisPriv.readObject();
		RSAPrivateKeySpec rsaPrivKeyspec = new RSAPrivateKeySpec(privateModulus2, privateExponent2);
		PrivateKey privateKey2 = keyFact.generatePrivate(rsaPrivKeyspec);
		
		// KeyParameters pour la clé publique
		RSAKeyParameters rsaKeyParamPub = new RSAKeyParameters(false, publicModulus2, publicExponent2);
		//KeyParameters	pour la clé privée	
		RSAKeyParameters rsaKeyParamPriv = new RSAKeyParameters(true, privateModulus2, privateExponent2);					
		RSABlindingFactorGenerator rsaBlindFactGen = new RSABlindingFactorGenerator();
		rsaBlindFactGen.init(rsaKeyParamPub);			
		BigInteger blindingFactor = rsaBlindFactGen.generateBlindingFactor();
		
		//Brouillage du message
		RSABlindingParameters rsaBlindParam = new RSABlindingParameters(rsaKeyParamPub, blindingFactor);
		RSABlindingEngine rsaBlingEngine = new RSABlindingEngine();
		rsaBlingEngine.init(true, rsaBlindParam); 					
		byte[] messageBrouille = rsaBlingEngine.processBlock(message, 0, message.length); 
		System.out.println("Le message brouillé : \n"+Hex.toHexString(messageBrouille));
        
		
		//Signature du message Brouillé
		RSAEngine sign = new RSAEngine();
		sign.init(true, rsaKeyParamPriv);	
		byte [] messageSigne = sign.processBlock(messageBrouille, 0, messageBrouille.length);
		System.out.println("Signature : \n"+Hex.toHexString(messageSigne));
		
		//Débrouillage du message Signé
		RSABlindingParameters rsaUnblindParam = new RSABlindingParameters(rsaKeyParamPriv, blindingFactor);
		RSABlindingEngine rsaBebBlindEngine = new RSABlindingEngine();
		rsaBebBlindEngine.init(false, rsaUnblindParam);			
		
		byte [] messageDebrouille = rsaBebBlindEngine.processBlock(messageSigne, 0, messageSigne.length);
		System.out.println("Message débrouillé : \n"+Hex.toHexString(messageDebrouille));
		
		//Vérification de la Signature du message débrouillé
		RSAEngine unsign = new RSAEngine();
		unsign.init(false, rsaKeyParamPub);
		byte [] messageVerif = unsign.processBlock(messageDebrouille, 0, messageDebrouille.length);
		
		System.out.println("Vérification de signature en hexa:"+Hex.toHexString(messageVerif));
		System.out.println("Vérification de signature en format texte:"+new String(messageVerif));
		System.out.println("Message initial: "+ new String(message));
		System.out.println("La signature est-elle verifiée?: "+new String(messageVerif).equals(new String(message)));
		
	}
}
