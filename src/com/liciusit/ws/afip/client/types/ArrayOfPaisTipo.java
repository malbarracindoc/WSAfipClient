
package com.liciusit.ws.afip.client.types;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ArrayOfPaisTipo complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ArrayOfPaisTipo">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="PaisTipo" type="{http://ar.gov.afip.dif.FEV1/}PaisTipo" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ArrayOfPaisTipo", propOrder = {
    "paisTipo"
})
public class ArrayOfPaisTipo {

    @XmlElement(name = "PaisTipo", nillable = true)
    protected List<PaisTipo> paisTipo;

    /**
     * Gets the value of the paisTipo property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the paisTipo property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getPaisTipo().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link PaisTipo }
     * 
     * 
     */
    public List<PaisTipo> getPaisTipo() {
        if (paisTipo == null) {
            paisTipo = new ArrayList<PaisTipo>();
        }
        return this.paisTipo;
    }

}
