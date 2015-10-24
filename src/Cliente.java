

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.sql.Date;
import java.text.DecimalFormat;
import java.util.Random;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.X509Extensions;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.security.auth.x500.X500Principal;
import javax.security.cert.X509Certificate;

import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

public class Cliente
{
	public double tAutenticacion=0.0;
	public double tRespuesta=0.0;
	public Double cpuUsage=0.0;
	public Cliente()throws Exception{
		
		//variable que avisa que se ejecute el programa
				boolean ejecutar = true;
				// socket que se crea
				Socket s = null;
				//escritor de flujo como output-stream
				PrintWriter escritor = null;
				//lector  de flujo como input-stream
				BufferedReader lector = null;
				
				
				
					//ip donde se trabajara el ip y el puerto 
					s = new Socket("Localhost", 443);
					// inicializacion del escritor y el lector
					escritor = new PrintWriter(s.getOutputStream(), true);
					lector = new BufferedReader(new InputStreamReader(s.getInputStream()));
				
				
				////BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

				// Variables que guardaran que llega y que se manda al servidor
				String fromServer;
				String forServer;

				// int contador=0;

				// se repetiraa el proceso mientras se pueda ejecutar el programa
				while (ejecutar) 
				{
					MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
					ObjectName name=ObjectName.getInstance("java.lang:type=OperatingSystem");
					//informar-empezar  (inicio de sesión de actualización de estado)
					forServer = "INFORMAR";
					escritor.println(forServer);
					System.out.println("Cliente: "+forServer);
					fromServer = lector.readLine();
					System.out.println("Servidor: "+fromServer);

					//mensaje de confirmacion  o rechazo
					if(fromServer==null||!fromServer.equalsIgnoreCase("EMPEZAR"))
					{
						System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
						ejecutar = false;
						break;
					}
					//algoritmos con los que se va a trabajar
					forServer = "ALGORITMOS:"+ALGORITMO+":"+HASH;
					escritor.println(forServer);
					System.out.println("Cliente: "+forServer);
					//Se recibe mensaje de confirmacion de soporte de los algoritmos
					fromServer = lector.readLine();
					System.out.println("Servidor: "+fromServer);
					if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK"))
					{
						System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
						ejecutar = false;
						break;
					}
					// se crea y envía un número aleatorio mas la palabra CERTPA
					Random r = new Random();
					Double numeroAleatorio= r.nextDouble();
					forServer = numeroAleatorio+":CERTPA";
					escritor.println(forServer);
					long tInicioAutenticacion= System.nanoTime();
					System.out.println("Cliente: "+forServer);

					//se agrega el provedor de certificados y se genera el par de llaves
					Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
					KeyPair k=MainClass.generateRSAKeyPair();
					keyPair=k;
					//se genera el certificado y se envia en un flojo de bytes
					java.security.cert.X509Certificate cert=MainClass.generateV3Certificate(k);
					byte[]mybyte=cert.getEncoded();
					s.getOutputStream().write(mybyte);
					s.getOutputStream().flush();
					System.out.println("Cliente: Se envió flujo");

					//se espera confirmacion de servidor en caso  optimista
					fromServer = lector.readLine();
					System.out.println("Servidor: "+fromServer);
					if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK"))
					{
						//hubo un error y el servidor no envio OK
						System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
						ejecutar = false;
						break;
					}

					//certificado servidor
					fromServer = lector.readLine();

					System.out.println("Servidor: "+fromServer);
					//El servidor no mando el numero aleatorio con  CERTSRV
					if(fromServer==null||!fromServer.endsWith(":CERTSRV"))
					{
						System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
						ejecutar = false;
						forServer = "RTA:ERROR";
						escritor.println(forServer);
						break;
					}

					//Si cumple el protocolo se procede a sacar el numero aleatorio
					Double numeroServidor=Double.parseDouble(fromServer.split(":")[0]);
					PublicKey llavePublicaServidor=null;
					try
					{
						//flujo que llega, sacar el certificado y la llave publica, para descifrar el flujo
						InputStream certificadoCervidor=new BufferedInputStream(s.getInputStream());
						CertificateFactory factory=CertificateFactory.getInstance("X.509");
						java.security.cert.Certificate certificadoServidor=factory.generateCertificate(certificadoCervidor);
						//LLave del servidor
						llavePublicaServidor=certificadoServidor.getPublicKey();
					}
					catch(Exception e)
					{
						//en caso de que haya una excepcion se envia ERROR al servidor
						ejecutar = false;
						forServer = "RTA:ERROR";
						escritor.println(forServer);
						break;
					}
					// de lo contrario se envia OK al servidor
					forServer = "RTA:OK";
					escritor.println(forServer);
					System.out.println("Cliente: "+forServer);

					//Nuestro numero  que nos llega cifrado
					fromServer = lector.readLine();
					long tfinAutenticacion = System.nanoTime();
					System.out.println("Servidor: "+fromServer);

					//VERIFICAR NUMEROS CIFRADOS, (nuestro numero original con el que nos envian cifrado)
					PublicKey llavePublicaServidor1= llavePublicaServidor;
					//convierte el numero de hexa a [] bytes
					byte[] numeroEnviaServidorEncriptado = hexaManager.fromHexa(fromServer);
					//se descifra el numero
					String nuestroNumeroOriginal=descifrar(numeroEnviaServidorEncriptado,llavePublicaServidor1);
					//System.out.println("Desencripto bien?: "+nuestroNumeroOriginal);
					//verificacion
					if(fromServer==null||!(numeroAleatorio+"").equalsIgnoreCase(nuestroNumeroOriginal))
					{
						System.out.println("Hubo un error al descifrar: " + "0.123456789"+" en lugar de: "+nuestroNumeroOriginal);
						forServer = "RTA:ERROR";
						escritor.println(forServer);
						ejecutar = false;
						break;
					}
					// si se cumple se envia un mensaje de verificacion
					forServer = "RTA:OK";
					escritor.println(forServer);
					System.out.println("Cliente: "+forServer);

					//Numero del cervidor que enviamos cifrado con nuestra llave privada

					//numero del servidor pasado a [] bytes, [] bytes cifrada
					byte[] by1 =(numeroServidor+"").getBytes();
					byte[] cby1=cifrar(by1,k.getPrivate());
					
					//se convierte a hexadecimal y se envia
					String numAenviar=hexaManager.toHexa(cby1);
					forServer = numAenviar;
					escritor.println(forServer);
					System.out.println("Cliente: "+forServer);
					
					//Se espera la respuesta del servidor
					fromServer = lector.readLine();
					System.out.println("Servidor: "+fromServer);
					if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK"))
					{
						System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
						ejecutar = false;
						break;
					}

					//Generación de llave de hash, y su debido encriptamiento
					String stringGenerador="estaCadenaGeneraLaLLAVE:)";
					SecretKey llaveHash = new SecretKeySpec(stringGenerador.getBytes(),0, stringGenerador.getBytes().length, HASH);

					//se cifra la llave  con la PUBLICA DEL SERVIDOR
					//y se envia al servidor doblemente cifrada
					byte[]cifrado1=cifrar(stringGenerador.getBytes(),llavePublicaServidor);
					//byte[]cifrado2=cliente.cifrar2(cifrado1,cliente.keyPair.getPrivate());
					byte[]cif=new byte[117];
					byte[]cif1=new byte[11];
					
					for (int i = 0; i < 117; i++) 
					{
						cif[i]=cifrado1[i];
					}
					//117-128-> cif1
					for (int i = 117; i < 128; i++) 
					{
						cif1[i-117]=cifrado1[i];
					}
					//cifrar primera parte del mensaje 0-117
					byte[]cifrado21=cifrar(cif,keyPair.getPrivate());
					//cifrar 2 parte del mensaje 117-128
					byte[]cifrado22=cifrar(cif1,keyPair.getPrivate());
					
					//SE UNEN  las dos partes del mensaje
					byte[]cifrado2=new byte[256];
					for (int i = 0; i < 128; i++) 
					{
						cifrado2[i]=cifrado21[i];
					}
					for (int i = 128; i < 256; i++) 
					{
						cifrado2[i]=cifrado22[i-128];
					} 
							//System.out.println((new String(cifrado2)).length());
					
					// se pasa a hexadecimal el mensaje que se enviara (doblemente cifrado)
					String llaveCifradaDosVecesb = hexaManager.toHexa(cifrado2);
							//System.out.println(llaveCifradaDosVecesb.length());
					forServer = "INIT:"+llaveCifradaDosVecesb;
					
					// se envia el mensaje + INIT
					escritor.println(forServer);
					long tInicio = System.nanoTime();
					System.out.println("Cliente: "+forServer);

					//se cifran  las ordenes 
					String mensajeOrdenes="ORDENES:1,2,3,4,5,6";
					byte[]cifrarOrdenesMensaje=cifrar((mensajeOrdenes).getBytes(),llavePublicaServidor);

					// se convierte to hex las ordenes
					String ordenesCifradasb = hexaManager.toHexa(cifrarOrdenesMensaje);
					forServer = ordenesCifradasb;
					// se envian las ordenes al Servidor (cifradas y convertidas a hex)
					escritor.println(forServer);
					System.out.println("Cliente: "+forServer);

					//se  inicializa el MAC
					Mac mac = Mac.getInstance(HASH);
					mac.init(llaveHash);
					
					//realiza el proceso final 
					byte[] bytes = mac.doFinal(("ORDENES:1,2,3,4,5,6").getBytes());
					String hmacOrdenes=new String(bytes);
					
					// se cifran las ordenes con la llave publica del SERVIDOR
					byte[]cifrarOrdenesMensajeHMACb=cifrar((hmacOrdenes).getBytes(),llavePublicaServidor);
					String cifrarOrdenesMensajeHMAC = hexaManager.toHexa(cifrarOrdenesMensajeHMACb);
					forServer = cifrarOrdenesMensajeHMAC;
					escritor.println(forServer);
					System.out.println("Cliente: "+forServer);

					fromServer = lector.readLine();
					long tFinal = System.nanoTime();
					System.out.println("Servidor: "+fromServer);
					// se espera la respuesta del servidor
					if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK"))
					{
						System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
						ejecutar = false;
						break;
					}
					ejecutar = false;
//					DecimalFormat formateador = new DecimalFormat("###.#########");
//					System.out.println("El tiempo de autenticacion es: " + formateador.format((double) (tfinAutenticacion-tInicioAutenticacion)/1000000000 ) + " segundos");
//					System.out.println("El tiempo de respuesta es: " + formateador.format((double) (tFinal-tInicio)/1000000000 ) + " segundos");
					tAutenticacion= (double) (tfinAutenticacion-tInicioAutenticacion)/1000000000 ;
					tRespuesta = (double) (tFinal-tInicio)/1000000000 ;
					
					AttributeList list = mbs.getAttributes(name, new String[]{"ProcessCpuLoad"});
					if(list.isEmpty()) System.out.println("esta vacio :" + Double.NaN);
					Attribute att  = (Attribute)list.get(0);
					Double value = (Double)att.getValue();
					
					if(value == -1.0) System.out.println("menos 1 :" + Double.NaN); // usually takes a couple of seconds before we get real values
					cpuUsage = (Double)(value*1000/10.0);
					System.out.println("CPUSAGE: " + cpuUsage);

				}
				escritor.close();
				lector.close();
				//stdIn.close();
				s.close();
		
				// cierre el socket y la entrada estándar
	}
	/**
	 * Algoritmo con el cual se  cifra la llave publica
	 */
	private final static String ALGORITMO="RSA";

	/**
	 * Algoritmo  que calcula un código de autenticación de mensajes basado en hash (HMAC) mediante la función hash  
	 */
	private final static String HASH="HMACMD5";

	/**
	 * Par de llaves del certificado. 
	 */
	private KeyPair keyPair;

	/**
	 * Manejador de mensajes hexadecimales
	 */
	private HexaManager hexaManager=new HexaManager( );

	/**
	 * Main de la clase del cliente con seguridad
	 * @param args
	 * @throws Exception
	 */
//	public static void main(String[] args) throws Exception
//	{
//		// se crea el cliente
//		Cliente cliente=new Cliente();
//		//variable que avisa que se ejecute el programa
//		boolean ejecutar = true;
//		// socket que se crea
//		Socket s = null;
//		//escritor de flujo como output-stream
//		PrintWriter escritor = null;
//		//lector  de flujo como input-stream
//		BufferedReader lector = null;
//
//		try
//		{
//			//ip donde se trabajara el ip y el puerto 
//			s = new Socket("Localhost", 443);
//			// inicializacion del escritor y el lector
//			escritor = new PrintWriter(s.getOutputStream(), true);
//			lector = new BufferedReader(new InputStreamReader(s.getInputStream()));
//		}
//		catch (Exception e)
//		{
//			System.err.println("Exception: " + e.getMessage());
//			System.exit(1);
//		}
//		////BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
//
//		// Variables que guardaran que llega y que se manda al servidor
//		String fromServer;
//		String forServer;
//
//		// int contador=0;
//
//		// se repetiraa el proceso mientras se pueda ejecutar el programa
//		while (ejecutar) 
//		{
//			//informar-empezar  (inicio de sesión de actualización de estado)
//			forServer = "INFORMAR";
//			escritor.println(forServer);
//			System.out.println("Cliente: "+forServer);
//			fromServer = lector.readLine();
//			System.out.println("Servidor: "+fromServer);
//
//			//mensaje de confirmacion  o rechazo
//			if(fromServer==null||!fromServer.equalsIgnoreCase("EMPEZAR"))
//			{
//				System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
//				ejecutar = false;
//				break;
//			}
//			//algoritmos con los que se va a trabajar
//			forServer = "ALGORITMOS:"+cliente.ALGORITMO+":"+cliente.HASH;
//			escritor.println(forServer);
//			System.out.println("Cliente: "+forServer);
//			//Se recibe mensaje de confirmacion de soporte de los algoritmos
//			fromServer = lector.readLine();
//			System.out.println("Servidor: "+fromServer);
//			if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK"))
//			{
//				System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
//				ejecutar = false;
//				break;
//			}
//			// se crea y envía un número aleatorio mas la palabra CERTPA
//			Random r = new Random();
//			Double numeroAleatorio= r.nextDouble();
//			forServer = numeroAleatorio+":CERTPA";
//			escritor.println(forServer);
//			System.out.println("Cliente: "+forServer);
//
//			//se agrega el provedor de certificados y se genera el par de llaves
//			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//			KeyPair k=MainClass.generateRSAKeyPair();
//			cliente.keyPair=k;
//			//se genera el certificado y se envia en un flojo de bytes
//			java.security.cert.X509Certificate cert=MainClass.generateV3Certificate(k);
//			byte[]mybyte=cert.getEncoded();
//			s.getOutputStream().write(mybyte);
//			s.getOutputStream().flush();
//			System.out.println("Cliente: Se envió flujo");
//
//			//se espera confirmacion de servidor en caso  optimista
//			fromServer = lector.readLine();
//			System.out.println("Servidor: "+fromServer);
//			if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK"))
//			{
//				//hubo un error y el servidor no envio OK
//				System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
//				ejecutar = false;
//				break;
//			}
//
//			//certificado servidor
//			fromServer = lector.readLine();
//
//			System.out.println("Servidor: "+fromServer);
//			//El servidor no mando el numero aleatorio con  CERTSRV
//			if(fromServer==null||!fromServer.endsWith(":CERTSRV"))
//			{
//				System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
//				ejecutar = false;
//				forServer = "RTA:ERROR";
//				escritor.println(forServer);
//				break;
//			}
//
//			//Si cumple el protocolo se procede a sacar el numero aleatorio
//			Double numeroServidor=Double.parseDouble(fromServer.split(":")[0]);
//			PublicKey llavePublicaServidor=null;
//			try
//			{
//				//flujo que llega, sacar el certificado y la llave publica, para descifrar el flujo
//				InputStream certificadoCervidor=new BufferedInputStream(s.getInputStream());
//				CertificateFactory factory=CertificateFactory.getInstance("X.509");
//				java.security.cert.Certificate certificadoServidor=factory.generateCertificate(certificadoCervidor);
//				//LLave del servidor
//				llavePublicaServidor=certificadoServidor.getPublicKey();
//			}
//			catch(Exception e)
//			{
//				//en caso de que haya una excepcion se envia ERROR al servidor
//				ejecutar = false;
//				forServer = "RTA:ERROR";
//				escritor.println(forServer);
//				break;
//			}
//			// de lo contrario se envia OK al servidor
//			forServer = "RTA:OK";
//			escritor.println(forServer);
//			System.out.println("Cliente: "+forServer);
//
//			//Nuestro numero  que nos llega cifrado
//			fromServer = lector.readLine();
//			System.out.println("Servidor: "+fromServer);
//
//			//VERIFICAR NUMEROS CIFRADOS, (nuestro numero original con el que nos envian cifrado)
//			PublicKey llavePublicaServidor1= llavePublicaServidor;
//			//convierte el numero de hexa a [] bytes
//			byte[] numeroEnviaServidorEncriptado = cliente.hexaManager.fromHexa(fromServer);
//			//se descifra el numero
//			String nuestroNumeroOriginal=cliente.descifrar(numeroEnviaServidorEncriptado,llavePublicaServidor1);
//			//System.out.println("Desencripto bien?: "+nuestroNumeroOriginal);
//			//verificacion
//			if(fromServer==null||!(numeroAleatorio+"").equalsIgnoreCase(nuestroNumeroOriginal))
//			{
//				System.out.println("Hubo un error al descifrar: " + "0.123456789"+" en lugar de: "+nuestroNumeroOriginal);
//				forServer = "RTA:ERROR";
//				escritor.println(forServer);
//				ejecutar = false;
//				break;
//			}
//			// si se cumple se envia un mensaje de verificacion
//			forServer = "RTA:OK";
//			escritor.println(forServer);
//			System.out.println("Cliente: "+forServer);
//
//			//Numero del cervidor que enviamos cifrado con nuestra llave privada
//
//			//numero del servidor pasado a [] bytes, [] bytes cifrada
//			byte[] by1 =(numeroServidor+"").getBytes();
//			byte[] cby1=cliente.cifrar(by1,k.getPrivate());
//			
//			//se convierte a hexadecimal y se envia
//			String numAenviar=cliente.hexaManager.toHexa(cby1);
//			forServer = numAenviar;
//			escritor.println(forServer);
//			System.out.println("Cliente: "+forServer);
//			
//			//Se espera la respuesta del servidor
//			fromServer = lector.readLine();
//			System.out.println("Servidor: "+fromServer);
//			if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK"))
//			{
//				System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
//				ejecutar = false;
//				break;
//			}
//
//			//Generación de llave de hash, y su debido encriptamiento
//			String stringGenerador="estaCadenaGeneraLaLLAVE:)";
//			SecretKey llaveHash = new SecretKeySpec(stringGenerador.getBytes(),0, stringGenerador.getBytes().length, cliente.HASH);
//
//			//se cifra la llave  con la PUBLICA DEL SERVIDOR
//			//y se envia al servidor doblemente cifrada
//			byte[]cifrado1=cliente.cifrar(stringGenerador.getBytes(),llavePublicaServidor);
//			//byte[]cifrado2=cliente.cifrar2(cifrado1,cliente.keyPair.getPrivate());
//			byte[]cif=new byte[117];
//			byte[]cif1=new byte[11];
//			
//			for (int i = 0; i < 117; i++) 
//			{
//				cif[i]=cifrado1[i];
//			}
//			//117-128-> cif1
//			for (int i = 117; i < 128; i++) 
//			{
//				cif1[i-117]=cifrado1[i];
//			}
//			//cifrar primera parte del mensaje 0-117
//			byte[]cifrado21=cliente.cifrar(cif,cliente.keyPair.getPrivate());
//			//cifrar 2 parte del mensaje 117-128
//			byte[]cifrado22=cliente.cifrar(cif1,cliente.keyPair.getPrivate());
//			
//			//SE UNEN  las dos partes del mensaje
//			byte[]cifrado2=new byte[256];
//			for (int i = 0; i < 128; i++) 
//			{
//				cifrado2[i]=cifrado21[i];
//			}
//			for (int i = 128; i < 256; i++) 
//			{
//				cifrado2[i]=cifrado22[i-128];
//			} 
//					//System.out.println((new String(cifrado2)).length());
//			
//			// se pasa a hexadecimal el mensaje que se enviara (doblemente cifrado)
//			String llaveCifradaDosVecesb = cliente.hexaManager.toHexa(cifrado2);
//					//System.out.println(llaveCifradaDosVecesb.length());
//			forServer = "INIT:"+llaveCifradaDosVecesb;
//			
//			// se envia el mensaje + INIT
//			escritor.println(forServer);
//			System.out.println("Cliente: "+forServer);
//
//			//se cifran  las ordenes 
//			String mensajeOrdenes="ORDENES:1,2,3,4,5,6";
//			byte[]cifrarOrdenesMensaje=cliente.cifrar((mensajeOrdenes).getBytes(),llavePublicaServidor);
//
//			// se convierte to hex las ordenes
//			String ordenesCifradasb = cliente.hexaManager.toHexa(cifrarOrdenesMensaje);
//			forServer = ordenesCifradasb;
//			// se envian las ordenes al Servidor (cifradas y convertidas a hex)
//			escritor.println(forServer);
//			System.out.println("Cliente: "+forServer);
//
//			//se  inicializa el MAC
//			Mac mac = Mac.getInstance(cliente.HASH);
//			mac.init(llaveHash);
//			
//			//realiza el proceso final 
//			byte[] bytes = mac.doFinal(("ORDENES:1,2,3,4,5,6").getBytes());
//			String hmacOrdenes=new String(bytes);
//			
//			// se cifran las ordenes con la llave publica del SERVIDOR
//			byte[]cifrarOrdenesMensajeHMACb=cliente.cifrar((hmacOrdenes).getBytes(),llavePublicaServidor);
//			String cifrarOrdenesMensajeHMAC = cliente.hexaManager.toHexa(cifrarOrdenesMensajeHMACb);
//			forServer = cifrarOrdenesMensajeHMAC;
//			escritor.println(forServer);
//			System.out.println("Cliente: "+forServer);
//
//			fromServer = lector.readLine();
//			System.out.println("Servidor: "+fromServer);
//			// se espera la respuesta del servidor
//			if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK"))
//			{
//				System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
//				ejecutar = false;
//				break;
//			}
//			ejecutar = false;
//		}
//		escritor.close();
//		lector.close();
//		//stdIn.close();
//		s.close();
//
//		// cierre el socket y la entrada estándar
//	}



	/**
	 * Metodo que se usa para cifrar una cadena de bytes con una llave privada 
	 * @param clearText cadena de bytes que se cifrara
	 * @param k cifrado con llave publica
	 * @return una cadena de bytes cifrados
	 */
	public byte[] cifrar(byte[] clearText,PrivateKey k) 
	{
		try {
			KeyPairGenerator generator =KeyPairGenerator.getInstance(ALGORITMO);
			generator.initialize(1024);
			//keyPair = generator.generateKeyPair();
			Cipher cipher = Cipher.getInstance(ALGORITMO);

			String s1 = new String (clearText);
			//System.out.println("clave original: " + s1);
			cipher.init(Cipher.ENCRYPT_MODE, k);
			long startTime = System.nanoTime();
			byte [] cipheredText = cipher.doFinal(clearText);
			long endTime = System.nanoTime();
			//System.out.println("clave cifrada: " + cipheredText);
			//System.out.println("Tiempo asimetrico: " +(endTime - startTime));
			return cipheredText;
		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}


	}

	/**
	 * 
	 * @param clearText
	 * @param k
	 * @return
	 */
	////	public byte[] cifrar2(byte[] clearText,PrivateKey k) 
	//	{
	//		try {
	//			KeyPairGenerator generator =KeyPairGenerator.getInstance(ALGORITMO);
	//			generator.initialize(1024);
	//			//keyPair = generator.generateKeyPair();
	//			Cipher cipher = Cipher.getInstance(ALGORITMO);
	//
	//			String s1 = new String (clearText);
	//			System.out.println("clave original: " + clearText.length);
	//			cipher.init(1, k);
	//			long startTime = System.nanoTime();
	//			byte [] cipheredText = cipher.doFinal(clearText);
	//			long endTime = System.nanoTime();
	//			//System.out.println("clave cifrada: " + cipheredText);
	//			//System.out.println("Tiempo asimetrico: " +(endTime - startTime));
	//			return cipheredText;
	//		}
	//		catch (Exception e) {
	//			e.printStackTrace();
	//			return null;
	//		}
	//
	//
	//	}
	//
	/**
	 * Metodo que se usa para cifrar una cadena de bytes con una llave publica 
	 * @param clearText cadena de bytes que se cifrara
	 * @param k cifrado con llave publica
	 * @return una cadena de bytes cifrados
	 */
	public byte[] cifrar(byte[] clearText,PublicKey k) 
	{
		try 
		{
			// se genera el par de llaves
			KeyPairGenerator generator =KeyPairGenerator.getInstance(ALGORITMO);
			generator.initialize(1024);
			//keyPair = generator.generateKeyPair();
			// permite el encriptamiento o des
			Cipher cipher = Cipher.getInstance(ALGORITMO);

			String s1 = new String (clearText);
			//System.out.println("clave original: " + s1);
			cipher.init(Cipher.ENCRYPT_MODE, k);
			long startTime = System.nanoTime();
			byte [] cipheredText = cipher.doFinal(clearText);
			long endTime = System.nanoTime();
			//			System.out.println("clave cifrada: " + cipheredText);
			//			System.out.println("Tiempo asimetrico: " +(endTime - startTime));
			return cipheredText;
		}
		catch (Exception e) 
		{
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}


	}

	/**
	 * Metodo que se usa para descifrar una cadena de bytes con una llave publica 
	 * @param clearText cadena de bytes que se cifrara
	 * @param k cifrado con llave publica
	 * @return una cadena de bytes descifrados
	 */
	public String descifrar(byte[] cipheredText,PublicKey k) 
	{
		String s3="";
		try {
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.DECRYPT_MODE, k);
			byte [] clearText = cipher.doFinal(cipheredText);
			s3 = new String(clearText);
			//			System.out.println("clave original: " + s3);
		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
		}
		return s3;
	}

}
