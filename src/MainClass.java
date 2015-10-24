
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * Clase para generar el certificado. 
 */
@SuppressWarnings("deprecation")	
public class MainClass 
{
	
	/**
	 * Metodo con el cual se genera un certificado, con la fecha actual, la fecha de validacion por dos años, el asunto del certificado, las extensiones
	 *   y el proveedor<br>
	 * @param pair llave publica y privada del certificado.
	 * @throws InvalidKeyException  excepcion que se lanza en caso de que la llave no cumpla con el tamaño, inicializaciòn <br>
	 * @throws NoSuchProviderException se lanza cuando el proveedor no esta disponible en el momento <br>
	 * @throws SignatureException 
	 * @return un certificado con la norma X509
	 */
  public static X509Certificate generateV3Certificate(KeyPair pair) throws InvalidKeyException,  NoSuchProviderException, SignatureException
  {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

    //numero serial del certificado, fecha de creacion, y fecha de caducidad
    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
    certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
    certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
    certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000));
    //asunto del certificado y llave publica del mismo
    certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
    certGen.setPublicKey(pair.getPublic());
    certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

    certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
    certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
    certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(  KeyPurposeId.id_kp_serverAuth));

    certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));

    return certGen.generateX509Certificate(pair.getPrivate(), "BC");
  }

  /**
   * Metodo principla, para provar si se crea el certificado <br>
   * @param args
   * @throws Exception
   */
  public static void main(String[] args) throws Exception 
  {
	  //proveedor del certificado
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    //generador de las llaves
    KeyPair pair = generateRSAKeyPair();
    X509Certificate cert = generateV3Certificate(pair);
    cert.checkValidity(new Date());
    cert.verify(cert.getPublicKey());
  }
  
  /**
   * Metodo generador del par de llaves del certificado, con agoritmo RSA.
   * @return el par de llaves del certificado. 
   * @throws Exception
   */
  public static KeyPair generateRSAKeyPair() throws Exception 
  {
	  //generador de las llaves con algoritmo RSA, con BC de proovedor
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
    kpGen.initialize(1024, new SecureRandom());
    return kpGen.generateKeyPair();
  }
}