/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/**
 *
 * @author Luka
 */
public class CertificateUtil {

    public void fillGeneratorData(X509V3CertificateGenerator cerGen, BasicInfo Info, DistinguishedName DN, UIExtensions Extensions, KeyPair pair) {

        cerGen.setPublicKey(pair.getPublic());
        String DNvalue = DN.create();
        cerGen.setSubjectDN(new X509Name(DNvalue));
        cerGen.setIssuerDN(new X509Name(DNvalue));
        cerGen.setSignatureAlgorithm(Info.signatureAlgorithm);
        cerGen.setSerialNumber(new BigInteger(Info.serial));
        cerGen.setNotBefore(Info.notBefore);
        cerGen.setNotAfter(Info.notAfter);

        // --- [1] Certificate Policies
        if (Extensions.certificatePoliciesValue.equals("") == false) {
            boolean isCritical = Extensions.certificatePolicies;
            PolicyQualifierInfo pqInfo = new PolicyQualifierInfo(Extensions.certificatePoliciesValue);
            PolicyInformation policyInfo = new PolicyInformation(PolicyQualifierId.id_qt_cps, new DERSequence(pqInfo));
            CertificatePolicies policies = new CertificatePolicies(policyInfo);
            cerGen.addExtension(Extension.certificatePolicies, isCritical, policies);
        }

        // --- [2] Issuer Alternative Names
        if (Extensions.issuerAlternativeNamesValue.length > 0) {
            List<GeneralName> names = new ArrayList();
            for (String name : Extensions.issuerAlternativeNamesValue) {
                names.add(new GeneralName(GeneralName.dNSName, name));
            }
            GeneralName[] listToArray = new GeneralName[names.size()];
            names.toArray(listToArray);
            GeneralNames issuerAltName = new GeneralNames(listToArray);
            cerGen.addExtension(Extension.issuerAlternativeName, false, issuerAltName);
        }

        // --- [3] Basic Constraints
        if (Extensions.isCertificateAuthority) {
            Integer pathLen = 0;
            if (Extensions.pathLength.compareTo("") > 0) {
                pathLen = Integer.parseInt(Extensions.pathLength);
            }
            BasicConstraints basicConstraint = new BasicConstraints(pathLen);
            cerGen.addExtension(Extension.basicConstraints, Extensions.basicConstraints, basicConstraint);
        }

    }

    public void setCertificatePolicies_SIGNING(X509v3CertificateBuilder certBuilder, X509Certificate certificateToSign) {
        try {

            // Certificate Policies
            String CPSURI = "";
            byte[] policyBytes = certificateToSign.getExtensionValue(Extension.certificatePolicies.toString());
            if (policyBytes != null) {
                // GET old
                CertificatePolicies policies = CertificatePolicies.getInstance(X509ExtensionUtil.fromExtensionValue(policyBytes));
                PolicyInformation[] policyInformation = policies.getPolicyInformation();
                for (PolicyInformation pInfo : policyInformation) {
                    ASN1Sequence policyQualifiers = (ASN1Sequence) pInfo.getPolicyQualifiers().getObjectAt(0);
                    CPSURI = policyQualifiers.getObjectAt(1).toString();
                }
                // SET new
                PolicyQualifierInfo pqInfo = new PolicyQualifierInfo(CPSURI);
                PolicyInformation policyInfo = new PolicyInformation(PolicyQualifierId.id_qt_cps, new DERSequence(pqInfo));
                CertificatePolicies newPolicies = new CertificatePolicies(policyInfo);
                boolean critical = false;
                for (String item : certificateToSign.getCriticalExtensionOIDs()) {
                    if (item.compareTo(Extension.certificatePolicies.toString()) == 0) {
                        critical = true;
                    }
                }
                certBuilder.addExtension(Extension.certificatePolicies, critical, newPolicies);
            }

        } catch (CertIOException ex) {
            Logger.getLogger(CertificateUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CertificateUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void setIssuerAlternativeNames_SIGNING(X509v3CertificateBuilder certBuilder, X509Certificate CAcert) {
        try {

            Collection CAnames = CAcert.getSubjectAlternativeNames();
            if (CAnames != null) {
                GeneralNames issuerAltName = new GeneralNames((GeneralName[]) CAnames.toArray());
                certBuilder.addExtension(Extension.issuerAlternativeName, false, issuerAltName);
            }

        } catch (CertificateParsingException | CertIOException ex) {
            Logger.getLogger(CertificateUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void setBasicConstraints_SIGNING(X509v3CertificateBuilder certBuilder, X509Certificate certificateToSign) {
        try {

            byte[] extVal = certificateToSign.getExtensionValue(Extension.basicConstraints.toString());
            if (extVal != null) {
                Object obj = new ASN1InputStream(extVal).readObject();
                extVal = ((DEROctetString) obj).getOctets();
                obj = new ASN1InputStream(extVal).readObject();
                BasicConstraints basicConstraints = BasicConstraints.getInstance((ASN1Sequence) obj);
                boolean critical = false;
                for (String item : certificateToSign.getCriticalExtensionOIDs()) {
                    if (item.compareTo(Extension.basicConstraints.toString()) == 0) {
                        critical = true;
                    }
                }
                certBuilder.addExtension(Extension.basicConstraints, critical, basicConstraints);
            }

        } catch (IOException ex) {
            Logger.getLogger(CertificateUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
