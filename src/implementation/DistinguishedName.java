/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import x509.v3.GuiV3;

/**
 *
 * @author Luka
 */
public class DistinguishedName {

    public String c;
    public String st;
    public String l;
    public String o;
    public String ou;
    public String cn;

    public DistinguishedName() {
        c = st = l = o = ou = cn = " ";
    }

    public DistinguishedName(GuiV3 access) {
        c = (access.getSubjectCountry().equals("") == true) ? " " : access.getSubjectCountry();
        st = (access.getSubjectState().equals("") == true) ? " " : access.getSubjectState();
        l = (access.getSubjectLocality().equals("") == true) ? " " : access.getSubjectLocality();
        o = (access.getSubjectOrganization().equals("") == true) ? " " : access.getSubjectOrganization();
        ou = (access.getSubjectOrganizationUnit().equals("") == true) ? " " : access.getSubjectOrganizationUnit();
        cn = (access.getSubjectCommonName().equals("") == true) ? " " : access.getSubjectCommonName();
    }

    public String create() {
        String value = "C=" + c + ",ST=" + st + ",L=" + l + ",O=" + o + ",OU=" + ou + ",CN=" + cn;
        return value;
    }

    public static void uiPreview(GuiV3 access, X509Certificate certificate) {
        try {
            LdapName ln = new LdapName(certificate.getSubjectDN().toString());
            for (String item : Collections.list(ln.getAll())) {
                String type = item.split("=")[0];
                String value;
                try {
                    value = item.split("=")[1];
                } catch (Exception e) {
                    value = "";
                }
                switch (type) {
                    case "CN":
                        access.setSubjectCommonName(value);
                        break;
                    case "C":
                        access.setSubjectCountry(value);
                        break;
                    case "L":
                        access.setSubjectLocality(value);
                        break;
                    case "O":
                        access.setSubjectOrganization(value);
                        break;
                    case "OU":
                        access.setSubjectOrganizationUnit(value);
                        break;
                    case "ST":
                        access.setSubjectState(value);
                        break;
                }
            }
        } catch (InvalidNameException ex) {
            Logger.getLogger(DistinguishedName.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
