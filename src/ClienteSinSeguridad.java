

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
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

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.X509Extensions;

import javax.crypto.*;
import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.security.auth.x500.X500Principal;
import javax.security.cert.X509Certificate;

import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

public class ClienteSinSeguridad 
{
	/**
	 * 
	 */
	private final static String ALGORITMO="RSA";

	/**
	 * 
	 */
	private KeyPair keyPair;


	/**
	 * 
	 * @param args
	 * @throws Exception
	 */
	public double tAutenticacion=0.0;
	public double tRespuesta=0.0;
	public Double cpuUsage=0.0;
	
	public ClienteSinSeguridad()throws Exception{
		boolean ejecutar = true;
		Socket s = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		
			s = new Socket("Localhost", 443);
			escritor = new PrintWriter(s.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(s.getInputStream()));
		
		//BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		String fromServer;
		String forServer;
		int contador=0;
		while (ejecutar) {
			MBeanServer mbs    = ManagementFactory.getPlatformMBeanServer();
			
				ObjectName name    = ObjectName.getInstance("java.lang:type=OperatingSystem");
				//informar-empezar
				forServer = "INFORMAR";
				escritor.println(forServer);
				//System.out.println("Cliente: "+forServer);
				fromServer = lector.readLine();
				//System.out.println("Servidor: "+fromServer);
				if(fromServer==null||!fromServer.equalsIgnoreCase("EMPEZAR"))
				{
					//System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
					ejecutar = false;
					forServer = "RTA:ERROR";
					escritor.println(forServer);
					//System.out.println("Cliente: "+forServer);
					break;
				}
				//algoritmos
				forServer = "ALGORITMOS:RSA:HMACMD5";
				escritor.println(forServer);
				//System.out.println("Cliente: "+forServer);
				fromServer = lector.readLine();
				//System.out.println("Servidor: "+fromServer);
				if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK")){
					//System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
					ejecutar = false;
					forServer = "RTA:ERROR";
					escritor.println(forServer);
					//System.out.println("Cliente: "+forServer);
					break;
				}
				//certificado que enviamos
				forServer = "0.123456789:CERTPA";
				long tInicioAtenticacion = System.nanoTime();
				escritor.println(forServer);
				//System.out.println("Cliente: "+forServer);
				Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
				KeyPair k=MainClass.generateRSAKeyPair();
				keyPair=k;
				java.security.cert.X509Certificate cert=MainClass.generateV3Certificate(k);
				byte[]mybyte=cert.getEncoded();
				s.getOutputStream().write(mybyte);
				s.getOutputStream().flush();
				//System.out.println("Cliente: Se envió flujo");
				fromServer = lector.readLine();
				//System.out.println("Servidor: "+fromServer);
				if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK")){
					//System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
					ejecutar = false;
					forServer = "RTA:ERROR";
					escritor.println(forServer);
					//System.out.println("Cliente: "+forServer);
					break;
				}


				//certificado servidor
				//como reconocerlo???

				fromServer = lector.readLine();


				//System.out.println("Servidor: "+fromServer);
				if(fromServer==null||!fromServer.endsWith(":CERTSRV")){
					//System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
					ejecutar = false;
					forServer = "RTA:ERROR";
					escritor.println(forServer);
					//System.out.println("Cliente: "+forServer);
					break;
				}

				Double numeroServidor=Double.parseDouble(fromServer.split(":")[0]);


				//flujo que llega, sacar el certificado y la llave publica
				InputStream certificadoCervidor=new BufferedInputStream(s.getInputStream());
				CertificateFactory factory=CertificateFactory.getInstance("X.509");
				java.security.cert.Certificate certificadoServidor=factory.generateCertificate(certificadoCervidor);
				PublicKey llavePublicaServidor=certificadoServidor.getPublicKey();

				forServer = "RTA:OK";
				escritor.println(forServer);
				//	System.out.println("Cliente: "+forServer);

				//Numero q nos llega
				fromServer = lector.readLine();
				//System.out.println("Servidor: "+fromServer);
				if(fromServer==null||!("0.123456789").equalsIgnoreCase(fromServer)){
					//System.out.println("Hubo un error al descifrar: " + "0.123456789"+" en lugar de: "+fromServer);
					ejecutar = false;
					forServer = "RTA:ERROR";
					escritor.println(forServer);
					//System.out.println("Cliente: "+forServer);
					break;
				}
				forServer = "RTA:OK";
				escritor.println(forServer);
				//System.out.println("Cliente: "+forServer);

				forServer = numeroServidor+"";
				escritor.println(forServer);
				//System.out.println("Cliente: "+forServer);
				fromServer = lector.readLine();
				long tFinAutenticacion = System.nanoTime();
				//System.out.println("Servidor: "+fromServer);
				if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK")){
					//System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
					ejecutar = false;
					forServer = "RTA:ERROR";
					escritor.println(forServer);
					//System.out.println("Cliente: "+forServer);
					break;
				}
				//		si da lo mismo	System.out.println("El tiempo de autenticacion es: " + ((double) (tFinAutenticacion-tInicioAtenticacion)/1000000000) + " en segundos");

				forServer = "INIT";
				escritor.println(forServer);
				long Tinicio = System.nanoTime();
				//System.out.println("Cliente: "+forServer);

				forServer = "ORDENES:1,2,3,4,5,6";
				escritor.println(forServer);
				//System.out.println("Cliente: "+forServer);

				forServer = "ORDENES:1,2,3,4,5,6";
				escritor.println(forServer);
				//System.out.println("Cliente: "+forServer);

				fromServer = lector.readLine();
				long tFinal = System.nanoTime();
				//System.out.println("Servidor: "+fromServer);
				if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK")){
					//System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
					ejecutar = false;
					forServer = "RTA:ERROR";
					escritor.println(forServer);
					//System.out.println("Cliente: "+forServer);
					break;
				}

				ejecutar = false;
				tAutenticacion= (double) (tFinAutenticacion-tInicioAtenticacion)/1000000000 ;
				tRespuesta = (double) (tFinal-Tinicio)/1000000000 ;
				
				AttributeList list = mbs.getAttributes(name, new String[]{"ProcessCpuLoad"});
				if(list.isEmpty()) System.out.println("esta vacio :" + Double.NaN);
				Attribute att  = (Attribute)list.get(0);
				Double value = (Double)att.getValue();
				
				if(value == -1.0) System.out.println("menos 1 :" + Double.NaN); // usually takes a couple of seconds before we get real values
				cpuUsage = (Double)(value*1000/10.0);
				System.out.println("CPUSAGE: " + cpuUsage);

	
		}
		// cierre el socket y la entrada estándar
		escritor.close();
		lector.close();
		//stdIn.close();
		s.close();

	
	}
	public static void main(String[] args) throws Exception 
	{
		ClienteSinSeguridad cliente=new ClienteSinSeguridad();}
//		boolean ejecutar = true;
//		Socket s = null;
//		PrintWriter escritor = null;
//		BufferedReader lector = null;
//		try {
//			s = new Socket("Localhost", 443);
//			escritor = new PrintWriter(s.getOutputStream(), true);
//			lector = new BufferedReader(new InputStreamReader(s.getInputStream()));
//		} catch (Exception e) {
//			System.err.println("Exception: " + e.getMessage());
//			System.exit(1);
//		}
//		//BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
//		String fromServer;
//		String forServer;
//		int contador=0;
//		while (ejecutar) {
//			MBeanServer mbs    = ManagementFactory.getPlatformMBeanServer();
//			try
//			{
//				ObjectName name    = ObjectName.getInstance("java.lang:type=OperatingSystem");
//				//informar-empezar
//				forServer = "INFORMAR";
//				escritor.println(forServer);
//				//System.out.println("Cliente: "+forServer);
//				fromServer = lector.readLine();
//				//System.out.println("Servidor: "+fromServer);
//				if(fromServer==null||!fromServer.equalsIgnoreCase("EMPEZAR"))
//				{
//					//System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
//					ejecutar = false;
//					forServer = "RTA:ERROR";
//					escritor.println(forServer);
//					//System.out.println("Cliente: "+forServer);
//					break;
//				}
//				//algoritmos
//				forServer = "ALGORITMOS:RSA:HMACMD5";
//				escritor.println(forServer);
//				//System.out.println("Cliente: "+forServer);
//				fromServer = lector.readLine();
//				//System.out.println("Servidor: "+fromServer);
//				if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK")){
//					//System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
//					ejecutar = false;
//					forServer = "RTA:ERROR";
//					escritor.println(forServer);
//					//System.out.println("Cliente: "+forServer);
//					break;
//				}
//				//certificado que enviamos
//				forServer = "0.123456789:CERTPA";
//				long tInicioAtenticacion = System.nanoTime();
//				escritor.println(forServer);
//				//System.out.println("Cliente: "+forServer);
//				Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//				KeyPair k=MainClass.generateRSAKeyPair();
//				cliente.keyPair=k;
//				java.security.cert.X509Certificate cert=MainClass.generateV3Certificate(k);
//				byte[]mybyte=cert.getEncoded();
//				s.getOutputStream().write(mybyte);
//				s.getOutputStream().flush();
//				//System.out.println("Cliente: Se envió flujo");
//				fromServer = lector.readLine();
//				//System.out.println("Servidor: "+fromServer);
//				if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK")){
//					//System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
//					ejecutar = false;
//					forServer = "RTA:ERROR";
//					escritor.println(forServer);
//					//System.out.println("Cliente: "+forServer);
//					break;
//				}
//
//
//				//certificado servidor
//				//como reconocerlo???
//
//				fromServer = lector.readLine();
//
//
//				//System.out.println("Servidor: "+fromServer);
//				if(fromServer==null||!fromServer.endsWith(":CERTSRV")){
//					//System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
//					ejecutar = false;
//					forServer = "RTA:ERROR";
//					escritor.println(forServer);
//					//System.out.println("Cliente: "+forServer);
//					break;
//				}
//
//				Double numeroServidor=Double.parseDouble(fromServer.split(":")[0]);
//
//
//				//flujo que llega, sacar el certificado y la llave publica
//				InputStream certificadoCervidor=new BufferedInputStream(s.getInputStream());
//				CertificateFactory factory=CertificateFactory.getInstance("X.509");
//				java.security.cert.Certificate certificadoServidor=factory.generateCertificate(certificadoCervidor);
//				PublicKey llavePublicaServidor=certificadoServidor.getPublicKey();
//
//				forServer = "RTA:OK";
//				escritor.println(forServer);
//				//	System.out.println("Cliente: "+forServer);
//
//				//Numero q nos llega
//				fromServer = lector.readLine();
//				//System.out.println("Servidor: "+fromServer);
//				if(fromServer==null||!("0.123456789").equalsIgnoreCase(fromServer)){
//					//System.out.println("Hubo un error al descifrar: " + "0.123456789"+" en lugar de: "+fromServer);
//					ejecutar = false;
//					forServer = "RTA:ERROR";
//					escritor.println(forServer);
//					//System.out.println("Cliente: "+forServer);
//					break;
//				}
//				forServer = "RTA:OK";
//				escritor.println(forServer);
//				//System.out.println("Cliente: "+forServer);
//
//				forServer = numeroServidor+"";
//				escritor.println(forServer);
//				//System.out.println("Cliente: "+forServer);
//				fromServer = lector.readLine();
//				long tFinAutenticacion = System.nanoTime();
//				//System.out.println("Servidor: "+fromServer);
//				if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK")){
//					//System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
//					ejecutar = false;
//					forServer = "RTA:ERROR";
//					escritor.println(forServer);
//					//System.out.println("Cliente: "+forServer);
//					break;
//				}
//				//		si da lo mismo	System.out.println("El tiempo de autenticacion es: " + ((double) (tFinAutenticacion-tInicioAtenticacion)/1000000000) + " en segundos");
//
//				forServer = "INIT";
//				escritor.println(forServer);
//				long Tinicio = System.nanoTime();
//				//System.out.println("Cliente: "+forServer);
//
//				forServer = "ORDENES:1,2,3,4,5,6";
//				escritor.println(forServer);
//				//System.out.println("Cliente: "+forServer);
//
//				forServer = "ORDENES:1,2,3,4,5,6";
//				escritor.println(forServer);
//				//System.out.println("Cliente: "+forServer);
//
//				fromServer = lector.readLine();
//				long tFinal = System.nanoTime();
//				//System.out.println("Servidor: "+fromServer);
//				if(fromServer==null||!fromServer.equalsIgnoreCase("RTA:OK")){
//					//System.out.println("Hubo un error de protocolo, el servidor respondió: " + fromServer);
//					ejecutar = false;
//					forServer = "RTA:ERROR";
//					escritor.println(forServer);
//					//System.out.println("Cliente: "+forServer);
//					break;
//				}
//
//				ejecutar = false;
//				DecimalFormat formateador = new DecimalFormat("####.#############");
//				System.out.println("El tiempo de autenticacion es: " + formateador.format((double) (tFinAutenticacion-tInicioAtenticacion)/1000000000) + " en segundos");
//				System.out.println("solution Time : " + formateador.format((double)(tFinal -Tinicio)/1000000000) + " en segundos");
//				//			System.out.println("El tiempo de actualizción es: " +( tFinal -Tinicio) + "nanoTime");
//
//				AttributeList list = mbs.getAttributes(name, new String[]{ "ProcessCpuLoad" });
//
//				if (list.isEmpty())     System.out.println( "esta vacio" + Double.NaN);;
//
//				Attribute att = (Attribute)list.get(0);
//				Double value  = (Double)att.getValue();
//
//				if (value == -1.0)      System.out.println( "menos 1 "+Double.NaN ); // usually takes a couple of seconds before we get real values
//
//				System.out.println( " no es menos ouno ni vacio " + ((double)(value * 1000) / 10.0));        // returns a percentage value with 1 decimal point precision
//			}
//			catch(Exception e)
//			{
//
//			}
//		}
//		// cierre el socket y la entrada estándar
//		escritor.close();
//		lector.close();
//		//stdIn.close();
//		s.close();
//
//	}
//



}
