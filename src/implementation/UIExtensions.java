/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import x509.v3.GuiV3;

/**
 *
 * @author Luka
 */
public class UIExtensions {

    public boolean certificatePolicies;
    public boolean anyPolicy;
    public String certificatePoliciesValue;

    public boolean issuerAlternativeNames;
    public String[] issuerAlternativeNamesValue;

    public boolean basicConstraints;
    public boolean isCertificateAuthority;
    public String pathLength;

    public UIExtensions(GuiV3 access) {
        certificatePolicies = access.isCritical(3);
        anyPolicy = access.getAnyPolicy();
        certificatePoliciesValue = access.getCpsUri();
        issuerAlternativeNames = access.isCritical(6);
        issuerAlternativeNamesValue = access.getAlternativeName(6);
        basicConstraints = access.isCritical(8);
        isCertificateAuthority = access.isCA();
        pathLength = access.getPathLen();
    }

    public static void uiPreview(GuiV3 access, X509Certificate certificate) {
        try {
            
            Set<String> criticals = certificate.getCriticalExtensionOIDs();
            if (criticals != null) {
                criticals.forEach((criticalElement) -> {
                    if (criticalElement.compareTo(Extension.certificatePolicies.toString()) == 0) {
                        access.setCritical(3, true);
                    }
                    if (criticalElement.compareTo(Extension.issuerAlternativeName.toString()) == 0) {
                        access.setCritical(6, true);
                    }
                    if (criticalElement.compareTo(Extension.basicConstraints.toString()) == 0) {
                        access.setCritical(8, true);
                    }
                });
            }

            // Certificate Policies
            byte[] policyBytes = certificate.getExtensionValue(Extension.certificatePolicies.toString());
            if (policyBytes != null) {
                CertificatePolicies policies = CertificatePolicies.getInstance(X509ExtensionUtil.fromExtensionValue(policyBytes));
                PolicyInformation[] policyInformation = policies.getPolicyInformation();
                for (PolicyInformation pInfo : policyInformation) {
                    ASN1Sequence policyQualifiers = (ASN1Sequence) pInfo.getPolicyQualifiers().getObjectAt(0);
                    access.setAnyPolicy(true);
                    access.setCpsUri(policyQualifiers.getObjectAt(1).toString());
                }
            }

            // Issuer Alternative Names
            Collection altNames = certificate.getIssuerAlternativeNames();
            if (altNames != null) {
                String altField = "";
                int i = 0;
                for (Iterator iterator = altNames.iterator(); iterator.hasNext();) {
                    List<Object> nameTypePair = (List<Object>) iterator.next();
                    String alternativeName = (String) nameTypePair.get(1);
                    altField += alternativeName;
                    if (i < altNames.size() - 1) {
                        altField += ",";
                    }
                    i++;
                }
                access.setAlternativeName(6, altField);
            }
            
            // Basic Constraints
            byte[] extVal = certificate.getExtensionValue(Extension.basicConstraints.toString());
            if (extVal != null) {
                Object obj = new ASN1InputStream(extVal).readObject();
                extVal = ((DEROctetString) obj).getOctets();
                obj = new ASN1InputStream(extVal).readObject();
                BasicConstraints basicConstraints = BasicConstraints.getInstance((ASN1Sequence) obj);
                //System.out.println("IS CA: " + basicConstraints.isCA());
                access.setCA(basicConstraints.isCA());
                if (basicConstraints.isCA()) {
                    access.setPathLen(basicConstraints.getPathLenConstraint().toString());
                }
            }
            
        } catch (CertificateParsingException | IOException ex) {
            Logger.getLogger(UIExtensions.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
