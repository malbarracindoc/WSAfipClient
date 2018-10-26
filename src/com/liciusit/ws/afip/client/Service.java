package com.liciusit.ws.afip.client;

import java.io.File;

import java.net.MalformedURLException;
import java.net.URL;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.namespace.QName;
import javax.xml.ws.WebEndpoint;
import javax.xml.ws.WebServiceClient;
import javax.xml.ws.WebServiceFeature;
// !DO NOT EDIT THIS FILE!
// This source file is generated by Oracle tools
// Contents may be subject to change
// For reporting problems, use the following
// Version = Oracle WebServices (11.1.1.0.0, build 130224.1947.04102)

@WebServiceClient(wsdlLocation="https://wswhomo.afip.gov.ar/wsfev1/service.asmx?WSDL",
  targetNamespace="http://ar.gov.afip.dif.FEV1/", name="Service")
public class Service
  extends javax.xml.ws.Service
{
  private static URL wsdlLocationURL;

  private static Logger logger;
  static
  {
    try
    {
      logger = Logger.getLogger("com.liciusit.ws.afip.client.Service");
      URL baseUrl = Service.class.getResource(".");
      if (baseUrl == null)
      {
        wsdlLocationURL =
            Service.class.getResource("https://wswhomo.afip.gov.ar/wsfev1/service.asmx?WSDL");
        if (wsdlLocationURL == null)
        {
          baseUrl = new File(".").toURL();
          wsdlLocationURL =
              new URL(baseUrl, "https://wswhomo.afip.gov.ar/wsfev1/service.asmx?WSDL");
        }
      }
      else
      {
                if (!baseUrl.getPath().endsWith("/")) {
         baseUrl = new URL(baseUrl, baseUrl.getPath() + "/");
}
                wsdlLocationURL =
            new URL(baseUrl, "https://wswhomo.afip.gov.ar/wsfev1/service.asmx?WSDL");
      }
    }
    catch (MalformedURLException e)
    {
      logger.log(Level.ALL,
          "Failed to create wsdlLocationURL using https://wswhomo.afip.gov.ar/wsfev1/service.asmx?WSDL",
          e);
    }
  }

  public Service()
  {
    super(wsdlLocationURL,
          new QName("http://ar.gov.afip.dif.FEV1/", "Service"));
  }

  public Service(URL wsdlLocation, QName serviceName)
  {
    super(wsdlLocation, serviceName);
  }

  @WebEndpoint(name="ServiceSoap")
  public com.liciusit.ws.afip.client.ServiceSoap getServiceSoap()
  {
    return (com.liciusit.ws.afip.client.ServiceSoap) super.getPort(new QName("http://ar.gov.afip.dif.FEV1/",
                                                                             "ServiceSoap"),
                                                                   com.liciusit.ws.afip.client.ServiceSoap.class);
  }

  @WebEndpoint(name="ServiceSoap")
  public com.liciusit.ws.afip.client.ServiceSoap getServiceSoap(WebServiceFeature... features)
  {
    return (com.liciusit.ws.afip.client.ServiceSoap) super.getPort(new QName("http://ar.gov.afip.dif.FEV1/",
                                                                             "ServiceSoap"),
                                                                   com.liciusit.ws.afip.client.ServiceSoap.class,
                                                                   features);
  }

  @WebEndpoint(name="ServiceSoap12")
  public com.liciusit.ws.afip.client.ServiceSoap getServiceSoap12()
  {
    return (com.liciusit.ws.afip.client.ServiceSoap) super.getPort(new QName("http://ar.gov.afip.dif.FEV1/",
                                                                             "ServiceSoap12"),
                                                                   com.liciusit.ws.afip.client.ServiceSoap.class);
  }

  @WebEndpoint(name="ServiceSoap12")
  public com.liciusit.ws.afip.client.ServiceSoap getServiceSoap12(WebServiceFeature... features)
  {
    return (com.liciusit.ws.afip.client.ServiceSoap) super.getPort(new QName("http://ar.gov.afip.dif.FEV1/",
                                                                             "ServiceSoap12"),
                                                                   com.liciusit.ws.afip.client.ServiceSoap.class,
                                                                   features);
  }
}
