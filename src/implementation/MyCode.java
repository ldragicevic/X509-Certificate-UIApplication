package implementation;

import code.GuiException;
import java.io.File;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

public class MyCode extends x509.v3.CodeV3 {

    private KeyStore keystore;
    private final String KS_TYPE = "BKS";
    private final String KS_FILE_PATH = "keystore.bks";
    private final String KS_PASSWORD = "root";
    private X509Certificate certificateToSign;
    private Util util;

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException, Exception {
        super(algorithm_conf, extensions_conf);
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        util = new Util("BKS", "keystore.bks", "root", this);
        return util.loadLocalKeystore(keystore);
    }

    @Override
    public void resetLocalKeystore() {
        util.resetLocalKeystore(keystore);
    }

    @Override
    public int loadKeypair(String keypair_name) {
        // Only V3 Certificates
        access.setVersion(2);
        return util.loadKeypair(keypair_name, access, keystore);
    }

    @Override
    public boolean saveKeypair(String string) {
        return util.saveKeypair(keystore, access, string);
    }

    @Override
    public boolean removeKeypair(String keypair_name) {
        return util.removeKeypair(keystore, keypair_name);
    }

    @Override
    public boolean importKeypair(String password, String filePath, String keypair_name) {
        return util.importKeyPair(keypair_name, filePath, password, keystore);
    }

    @Override
    public boolean exportKeypair(String keypair_name, String filePath, String password) {
        return util.exportKeyPair(keypair_name, filePath, password, keystore);
    }

    @Override
    public List<String> getIssuers(String keypair_name) {
        return util.getIssuers(keypair_name, keystore);
    }

    @Override
    @SuppressWarnings("empty-statement")
    public String getIssuer(String keypair_name) {
        String issuerDN = util.getIssuerDN(keystore, keypair_name);
        return issuerDN;
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String keypair_name) {
        String issuerPublicAlg = util.getIssuerPublicKeyAlg(keystore, keypair_name);
        return issuerPublicAlg;
    }

    @Override
    public int getRSAKeyLength(String keypair_name) {
        int keyLength = util.getRSAKeyLength(keystore, keypair_name);
        return keyLength;
    }

    @Override
    public boolean generateCSR(String keypair_name) {
        boolean result = util.generateCSR(keystore, keypair_name);
        return result;
    }

    public void setCurrentSigningCertificate(X509Certificate certificate) {
        certificateToSign = certificate;
    }

    @Override
    public boolean signCertificate(String issuer, String algorithm) {
        boolean result = util.signCSR(keystore, certificateToSign, issuer, algorithm);
        return result;
    }

    @Override
    public boolean importCertificate(File file, String keypair_name) {
        boolean result = util.importCertificate(keystore, file, keypair_name);
        return result;
    }

    @Override
    public boolean exportCertificate(File file, int encoding) {
        boolean result = util.exportCertificate(keystore, file, encoding);
        return result;
    }

}
