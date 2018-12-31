package com.liciuit.client.afip.wsaa;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;

import javax.xml.rpc.ParameterMode;

import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.axis.encoding.Base64;
import org.apache.axis.encoding.XMLType;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.sun.org.apache.xerces.internal.jaxp.datatype.XMLGregorianCalendarImpl;

public class AfipWsaaClient {
	
	static String invokeWsaa (byte [] LoginTicketRequest_xml_cms, String endpoint) throws Exception {
		
		String LoginTicketResponse = null;
		try {
		  
			Service service = new Service();
			Call call = (Call) service.createCall();
	
			//
			// Preparamos la llamada al Web service
			//
			call.setTargetEndpointAddress( new java.net.URL(endpoint) );
			call.setOperationName("loginCms");
			call.addParameter( "request", XMLType.XSD_STRING, ParameterMode.IN );
			call.setReturnType( XMLType.XSD_STRING );
	
			//
			// Hacer la llamada real y asignar la respuesta a una cadena
			//
			LoginTicketResponse = (String) call.invoke(new Object [] { 
				Base64.encode (LoginTicketRequest_xml_cms) } );


		} catch (Exception e) {
			e.printStackTrace();
		}        
		return (LoginTicketResponse);
	}

	//
	// Crea un  mensaje tipo CMS
	//
	public static byte [] createCMS (String p12file, String p12pass, String signer, String dstDN, String service, Long TicketTime) {

		PrivateKey pKey = null;
		X509Certificate pCertificate = null;
		byte [] asn1_cms = null;
		CertStore cstore = null;
		String LoginTicketRequest_xml;
		String SignerDN = null;

		try {
			// Creamos un keystore usando la keys para pkcs#12 p12file
			KeyStore ks = KeyStore.getInstance("pkcs12");
			FileInputStream p12stream = new FileInputStream ( p12file ) ;
			ks.load(p12stream, p12pass.toCharArray());
			p12stream.close();

			// Obtener certificado y clave privada del KeyStore
			pKey = (PrivateKey) ks.getKey(signer, p12pass.toCharArray());
			pCertificate = (X509Certificate)ks.getCertificate(signer);
			SignerDN = pCertificate.getSubjectDN().toString();

			// Crea una lista de Certificados para incluir en el CMS final.
			ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
			certList.add(pCertificate);

			if (Security.getProvider("BC") == null) {
				Security.addProvider(new BouncyCastleProvider());
			}

			cstore = CertStore.getInstance("Collection", new CollectionCertStoreParameters (certList), "BC");
		} 
		catch (Exception e) {
			e.printStackTrace();
		} 

		//
		// Creamos un XML Message
		// 
		LoginTicketRequest_xml = create_LoginTicketRequest(SignerDN, dstDN, service, TicketTime);
		
		//
		// Creamos un CMS Message
		//
		try {
			
			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

			// Añadimos una firma al mensaje
			gen.addSigner(pKey, pCertificate, CMSSignedDataGenerator.DIGEST_SHA1);

			// Agregamos un certificado al mensaje
      		gen.addCertificatesAndCRLs(cstore);

			CMSProcessable data = new CMSProcessableByteArray(LoginTicketRequest_xml.getBytes());
			CMSSignedData signed = gen.generate(data, true, "BC");	

			asn1_cms = signed.getEncoded();
		} 
		catch (Exception e) {
			e.printStackTrace();
		} 
	
		return (asn1_cms);
	}
	
	//
	// Creamos el XML para enviar a AFIP wsaa
	// 	
	public static String create_LoginTicketRequest (String SignerDN, String dstDN, String service, Long TicketTime) {

		String LoginTicketRequest_xml;

		Date GenTime = new Date();
		GregorianCalendar gentime = new GregorianCalendar();
		GregorianCalendar exptime = new GregorianCalendar();
		String UniqueId = new Long(GenTime.getTime() / 1000).toString();
		
		exptime.setTime(new Date(GenTime.getTime()+TicketTime));
		
		XMLGregorianCalendarImpl XMLGenTime = new XMLGregorianCalendarImpl(gentime);
		XMLGregorianCalendarImpl XMLExpTime = new XMLGregorianCalendarImpl(exptime);

		LoginTicketRequest_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
						+"<loginTicketRequest version=\"1.0\">"
			+"<header>"
			+"<source>" + SignerDN + "</source>"
			+"<destination>" + dstDN + "</destination>"
			+"<uniqueId>" + UniqueId + "</uniqueId>"
			+"<generationTime>" + XMLGenTime + "</generationTime>"
			+"<expirationTime>" + XMLExpTime + "</expirationTime>"
			+"</header>"
			+"<service>" + service + "</service>"
			+"</loginTicketRequest>";
		
		//System.out.println("TRA: " + LoginTicketRequest_xml);
		
		return (LoginTicketRequest_xml);
	}
	
}
