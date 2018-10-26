
package com.liciusit.ws.afip.client.types;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for CbteAsoc complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CbteAsoc">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Tipo" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="PtoVta" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="Nro" type="{http://www.w3.org/2001/XMLSchema}long"/>
 *         &lt;element name="Cuit" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CbteAsoc", propOrder = {
    "tipo",
    "ptoVta",
    "nro",
    "cuit"
})
public class CbteAsoc {

    @XmlElement(name = "Tipo")
    protected int tipo;
    @XmlElement(name = "PtoVta")
    protected int ptoVta;
    @XmlElement(name = "Nro")
    protected long nro;
    @XmlElement(name = "Cuit")
    protected String cuit;

    /**
     * Gets the value of the tipo property.
     * 
     */
    public int getTipo() {
        return tipo;
    }

    /**
     * Sets the value of the tipo property.
     * 
     */
    public void setTipo(int value) {
        this.tipo = value;
    }

    /**
     * Gets the value of the ptoVta property.
     * 
     */
    public int getPtoVta() {
        return ptoVta;
    }

    /**
     * Sets the value of the ptoVta property.
     * 
     */
    public void setPtoVta(int value) {
        this.ptoVta = value;
    }

    /**
     * Gets the value of the nro property.
     * 
     */
    public long getNro() {
        return nro;
    }

    /**
     * Sets the value of the nro property.
     * 
     */
    public void setNro(long value) {
        this.nro = value;
    }

    /**
     * Gets the value of the cuit property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCuit() {
        return cuit;
    }

    /**
     * Sets the value of the cuit property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCuit(String value) {
        this.cuit = value;
    }

}
