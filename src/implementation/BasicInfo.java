/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import java.security.cert.X509Certificate;
import java.util.Date;
import x509.v3.GuiV3;

/**
 *
 * @author Luka
 */
public class BasicInfo {

    public String serial;
    public Date notBefore;
    public Date notAfter;
    public int keyLength;
    public String signatureAlgorithm;
    public String keyAlgorithm;

    public BasicInfo(GuiV3 access) {
        serial = access.getSerialNumber();
        notBefore = access.getNotBefore();
        notAfter = access.getNotAfter();
        keyLength = Integer.parseInt(access.getPublicKeyParameter());
        signatureAlgorithm = access.getPublicKeySignatureAlgorithm();
        keyAlgorithm = access.getPublicKeyAlgorithm();
    }

    public static void uiPreview(GuiV3 access, X509Certificate certificate, X509Certificate issuer) {
        access.setSerialNumber(certificate.getSerialNumber().toString());
        access.setNotBefore(certificate.getNotBefore());
        access.setNotAfter(certificate.getNotAfter());
        access.setPublicKeySignatureAlgorithm(certificate.getSigAlgName());
        access.setIssuerSignatureAlgorithm((issuer == null) ? certificate.getSigAlgName() : issuer.getSigAlgName());
        access.setSubjectSignatureAlgorithm(certificate.getSigAlgName());
    }

}
