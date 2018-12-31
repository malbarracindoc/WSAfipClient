package fev1.dif.afip.gov.ar;

import java.net.MalformedURLException;
import java.net.URL;
import javax.xml.namespace.QName;
import javax.xml.ws.WebEndpoint;
import javax.xml.ws.WebServiceClient;
import javax.xml.ws.WebServiceFeature;

/**
 * Web Service orientado  al  servicio  de Facturacion electronica RG2485 V1
 *
 * This class was generated by Apache CXF 3.2.7
 * 2018-12-31T14:57:55.242+01:00
 * Generated source version: 3.2.7
 *
 */
@WebServiceClient(name = "Service",
                  wsdlLocation = "file:/C:/desarrollo/java/workspace/proxy-client-ws-afip/src/main/resources/service.wsdl",
                  targetNamespace = "http://ar.gov.afip.dif.FEV1/")
public class Service extends javax.xml.ws.Service {

    public final static URL WSDL_LOCATION;

    public final static QName SERVICE = new QName("http://ar.gov.afip.dif.FEV1/", "Service");
    public final static QName ServiceSoap = new QName("http://ar.gov.afip.dif.FEV1/", "ServiceSoap");
    public final static QName ServiceSoap12 = new QName("http://ar.gov.afip.dif.FEV1/", "ServiceSoap12");
    static {
        URL url = null;
        try {
            url = new URL("file:/C:/desarrollo/java/workspace/proxy-client-ws-afip/src/main/resources/service.wsdl");
        } catch (MalformedURLException e) {
            java.util.logging.Logger.getLogger(Service.class.getName())
                .log(java.util.logging.Level.INFO,
                     "Can not initialize the default wsdl from {0}", "file:/C:/desarrollo/java/workspace/proxy-client-ws-afip/src/main/resources/service.wsdl");
        }
        WSDL_LOCATION = url;
    }

    public Service(URL wsdlLocation) {
        super(wsdlLocation, SERVICE);
    }

    public Service(URL wsdlLocation, QName serviceName) {
        super(wsdlLocation, serviceName);
    }

    public Service() {
        super(WSDL_LOCATION, SERVICE);
    }

    public Service(WebServiceFeature ... features) {
        super(WSDL_LOCATION, SERVICE, features);
    }

    public Service(URL wsdlLocation, WebServiceFeature ... features) {
        super(wsdlLocation, SERVICE, features);
    }

    public Service(URL wsdlLocation, QName serviceName, WebServiceFeature ... features) {
        super(wsdlLocation, serviceName, features);
    }




    /**
     *
     * @return
     *     returns ServiceSoap
     */
    @WebEndpoint(name = "ServiceSoap")
    public ServiceSoap getServiceSoap() {
        return super.getPort(ServiceSoap, ServiceSoap.class);
    }

    /**
     *
     * @param features
     *     A list of {@link javax.xml.ws.WebServiceFeature} to configure on the proxy.  Supported features not in the <code>features</code> parameter will have their default values.
     * @return
     *     returns ServiceSoap
     */
    @WebEndpoint(name = "ServiceSoap")
    public ServiceSoap getServiceSoap(WebServiceFeature... features) {
        return super.getPort(ServiceSoap, ServiceSoap.class, features);
    }


    /**
     *
     * @return
     *     returns ServiceSoap
     */
    @WebEndpoint(name = "ServiceSoap12")
    public ServiceSoap getServiceSoap12() {
        return super.getPort(ServiceSoap12, ServiceSoap.class);
    }

    /**
     *
     * @param features
     *     A list of {@link javax.xml.ws.WebServiceFeature} to configure on the proxy.  Supported features not in the <code>features</code> parameter will have their default values.
     * @return
     *     returns ServiceSoap
     */
    @WebEndpoint(name = "ServiceSoap12")
    public ServiceSoap getServiceSoap12(WebServiceFeature... features) {
        return super.getPort(ServiceSoap12, ServiceSoap.class, features);
    }

}
