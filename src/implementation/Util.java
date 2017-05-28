/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import x509.v3.GuiV3;

/**
 *
 * @author Luka
 */
public class Util {

    private final String KS_TYPE;
    private final String KS_FILE_PATH;
    private final String KS_PASSWORD;
    private final MyCode myCode;
    private PKCS10CertificationRequest csrRequest;
    private String csrRequestAlias;
    private String loadedKeyPair;

    public Util(String type, String path, String password, MyCode myCodeInit) {
        KS_TYPE = type;
        KS_FILE_PATH = path;
        KS_PASSWORD = password;
        myCode = myCodeInit;
    }

    public KeyStore init(KeyStore keystore) {
        try {
            if (keystore == null) {
                keystore = KeyStore.getInstance(KS_TYPE, "BC");
                if (new File(KS_FILE_PATH).exists() == true) {
                    keystore.load(new FileInputStream(KS_FILE_PATH), KS_PASSWORD.toCharArray());
                } else {
                    keystore.load(null, null);
                }
            }
            return keystore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | NoSuchProviderException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public Enumeration<String> loadLocalKeystore(KeyStore keystore) {
        /*
        Метода loadLocalKeystore() треба да учита локално складиште кључева и као повратну
        вредност врати листу алиас-а за парове кључева/сертификатe у keystore-у.
         */
        try {
            // ADDING BouncyCastle 
            Security.addProvider(new BouncyCastleProvider());
            if (keystore == null) {
                keystore = KeyStore.getInstance(KS_TYPE, "BC");
                if (new File(KS_FILE_PATH).exists()) {
                    keystore.load(new FileInputStream(KS_FILE_PATH), KS_PASSWORD.toCharArray());
                } else {
                    keystore.load(null, null);
                    keystore.store(new FileOutputStream(KS_FILE_PATH), KS_PASSWORD.toCharArray());
                }
            }
            return keystore.aliases();
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | NoSuchProviderException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public void resetLocalKeystore(KeyStore keystore) {
        /*
        Метода resetLocalKeystore() треба да обрише локално складиште кључева.
         */
        try {
            keystore = init(keystore);
            for (String alias : Collections.list(keystore.aliases())) {
                keystore.deleteEntry(alias);
            }
            keystore.store(new FileOutputStream(KS_FILE_PATH), KS_PASSWORD.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public int loadKeypair(String alias, GuiV3 access, KeyStore keystore) {
        /*
        Метода loadKeypair(String keypair_name) треба да учита податке о пару
        кључева/сертификату који је сачуван под алиасом keypair_name из локалног keystore-a и
        прикаже их на графичком корисничком интерфејсу. Повратна вредност методе је
        целобројна вредност која означава успешност операције. Метода враћа -1 у случају
        грешке, 0 у случају да сертификат сачуван под тим алиасом није потписан, 1 у случају да је
        потписан, 2 у случају да је у питању увезени trusted сертификат.
         */
        try {
            keystore = init(keystore);
            X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
            Certificate[] chain = keystore.getCertificateChain(alias);
            X509Certificate issuerCert = (chain != null && chain.length > 1) ? (X509Certificate) chain[1] : null;
            try {
                access.setIssuer(certificate.getIssuerDN().toString());
            } catch (Exception e) {
            }

            DistinguishedName.uiPreview(access, certificate);
            BasicInfo.uiPreview(access, certificate, issuerCert);
            UIExtensions.uiPreview(access, certificate);

            loadedKeyPair = alias;

            // TRUSTED AKO JE KEYUSAGE [5] -> DOZVOLJEN DA POTPISUJE DRUGE
            boolean[] keyUsage = certificate.getKeyUsage();
            int CAlength = certificate.getBasicConstraints();
            //System.out.println("keyusage: " + ((keyUsage == null) ? "x" : keyUsage[5]));
            //System.out.println("caleng:" + CAlength);
            if (keyUsage != null && keyUsage[5]) {
                //System.out.println("RETURN 2");
                return 2;   // CA certificate = trusted (2)
            } else if (certificate.getSubjectDN().equals(certificate.getIssuerDN()) == false) {
                //System.out.println("RETURN 1");
                return 1;   // Signed not CA (1)
            } else {
                return 0;   // Not signed (0)
            }
        } catch (KeyStoreException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            return -1;
        }

    }

    public boolean saveKeypair(KeyStore keystore, GuiV3 access, String keypair_name) {
        /*
        Метода saveKeypair(String keypair_name) треба да на основу података са графичког
        корисничког интерфејса генерише и сачува нови пар кључева у локалном keystore-у под
        алиасом са вредношћу keypair_name. Повратна вредност методе означава успешност
        операције, false у случају грешке.
         */
        try {
            keystore = init(keystore);
            // BasicInfo, DistinguishedName, Extensions passed from UI
            BasicInfo Info = new BasicInfo(access);
            DistinguishedName DN = new DistinguishedName(access);
            UIExtensions Extensions = new UIExtensions(access);
            CertificateUtil CertUtil = new CertificateUtil();
            
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(Info.keyAlgorithm);
            keyGen.initialize(Info.keyLength);
            KeyPair pair = keyGen.generateKeyPair();
            X509V3CertificateGenerator cerGen = new X509V3CertificateGenerator();
            CertUtil.fillGeneratorData(cerGen, Info, DN, Extensions, pair);
            // New Certificate
            X509Certificate cert = cerGen.generate(pair.getPrivate(), "BC");
            keystore.setKeyEntry(keypair_name, pair.getPrivate(), KS_PASSWORD.toCharArray(), new Certificate[]{cert});
            keystore.store(new FileOutputStream(KS_FILE_PATH), KS_PASSWORD.toCharArray());
            return true;

        } catch (NoSuchAlgorithmException | CertificateEncodingException | IllegalStateException | SignatureException | InvalidKeyException ex) {
            Logger.getLogger(Util.class
                    .getName()).log(Level.SEVERE, null, ex);
            return false;

        } catch (KeyStoreException | IOException | CertificateException | NoSuchProviderException ex) {
            Logger.getLogger(Util.class
                    .getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }

    public boolean removeKeypair(KeyStore keystore, String keypair_name) {
        /*
        Метода removeKeypair(String keypair_name) треба да из локалног keystore-a обрише пар
        кључева/сертификат који је сачуван под алиасом keypair_name. Повратна вредност
        методе означава успешност операције, false у случају грешке.
         */
        try {
            keystore = init(keystore);
            keystore.deleteEntry(keypair_name);
            keystore.store(new FileOutputStream(KS_FILE_PATH), KS_PASSWORD.toCharArray());
            return true;

        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class
                    .getName()).log(Level.SEVERE, null, ex);
            return false;

        } catch (FileNotFoundException ex) {
            Logger.getLogger(Util.class
                    .getName()).log(Level.SEVERE, null, ex);
            return false;

        } catch (IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(Util.class
                    .getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }

    public boolean importKeyPair(String password, String filePath, String alias, KeyStore keystore) {
        /*
        Метода importKeypair(String keypair_name, String file, String password) треба да из фајла са
        путањом file учита постојећи пар кључева који је сачуван у PKCS#12 формату и заштићен
        лозинком и сачува га у локални keystore под алиасом keypair_name. Повратна вредност
        методе означава успешност операције, false у случају грешке.
         */
        try {
            // import keystore
            KeyStore importKeyStore = KeyStore.getInstance("PKCS12", "BC");
            importKeyStore.load(new FileInputStream(filePath), password.toCharArray());
            int importAliasNo = Collections.list(importKeyStore.aliases()).size();
            // Importing keystore must contain 1 alias
            if (importAliasNo != 1) {
                return false;
            } else {
                String existingAlias = Collections.list(importKeyStore.aliases()).get(0);
                ProtectionParameter protection = new KeyStore.PasswordProtection(password.toCharArray());
                PrivateKeyEntry entry = (PrivateKeyEntry) importKeyStore.getEntry(existingAlias, protection);
                // local keystore
                keystore = init(keystore);
                keystore.setKeyEntry(alias, entry.getPrivateKey(), KS_PASSWORD.toCharArray(), entry.getCertificateChain());
                keystore.store(new FileOutputStream(KS_FILE_PATH), KS_PASSWORD.toCharArray());
                return true;
            }

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException | IOException | CertificateException | NoSuchProviderException ex) {
            Logger.getLogger(Util.class
                    .getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }

    public boolean exportKeyPair(String alias, String filePath, String password, KeyStore keystore) {
        /*
        Метода exportKeypair(String keypair_name, String file, String password) треба да постојећи
        пар кључева који је у локалном keystore-у сачуван под алиасом keypair_name извезе у фајл
        са путањом file у PKCS#12 формату и заштити лозинком. Повратна вредност методе
        означава успешност операције, false у случају грешке.
         */
        try {
            // local keystore
            keystore = init(keystore);
            ProtectionParameter protection = new KeyStore.PasswordProtection(KS_PASSWORD.toCharArray());
            PrivateKeyEntry entry = (PrivateKeyEntry) keystore.getEntry(alias, protection);

            // export keystore
            Certificate[] chainToExport = entry.getCertificateChain();

            KeyStore exportKeyStore = KeyStore.getInstance("PKCS12", "BC");
            exportKeyStore.load(null, null);
            exportKeyStore.setKeyEntry(alias, entry.getPrivateKey(), password.toCharArray(), chainToExport);
            exportKeyStore.store(new FileOutputStream(filePath + ".p12"), password.toCharArray());
            return true;
        } catch (KeyStoreException ex) {
            return false;

        } catch (IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | NoSuchProviderException ex) {
            Logger.getLogger(Util.class
                    .getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }

    public List<String> getIssuers(String keypair_name, KeyStore keystore) {
        /*
        Метода getIssuers(String keypair_name) треба да врати листу alias-а свих сертификата
        сачуваних у локалном keystore-у који могу да потпишу сертификат који је у локалном
        keystore-у сачуван под алиасом keypair_name.
         */
        try {
            keystore = init(keystore);
            List<String> possibleIssuers = new LinkedList<>();
            for (String alias : Collections.list(keystore.aliases())) {
                X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
                // MUST BE CA && NOT ITSELF
                if (cert.getBasicConstraints() > 0 && !keypair_name.equals(alias)) {
                    possibleIssuers.add(alias);
                }
            }
            return possibleIssuers;

        } catch (KeyStoreException ex) {
            Logger.getLogger(Util.class
                    .getName()).log(Level.SEVERE, null, ex);
            return null;
        }

    }

    public int getRSAKeyLength(KeyStore keystore, String keypair_name) {
        /*
        Метода getRSAKeyLength (String keypair_name) треба да врати дужину кључа сертификата
        који је у локалном keystore-у сачуван под алиасом keypair_name у случају да је алгоритам
        који је коришћен за генерисање пара кључева овог сертификата ’’RSA’’. 
        Користи се за проверавање дозвољених комбинација дужине кључева RSA алгоритма и hash алгоритама.
         */
        try {
            keystore = init(keystore);
            ProtectionParameter protection = new KeyStore.PasswordProtection(KS_PASSWORD.toCharArray());
            PrivateKeyEntry entry = (PrivateKeyEntry) keystore.getEntry(keypair_name, protection);
            String keyAlgorithm = entry.getPrivateKey().getAlgorithm();
            if (keyAlgorithm.equals("RSA")) {
                RSAPublicKey rsaPK = (RSAPublicKey) keystore.getCertificate(keypair_name).getPublicKey();
                int keysize = rsaPK.getModulus().bitLength();
                return keysize;
            } else {
                throw new NoSuchAlgorithmException("Not RSA key algorithm");

            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException ex) {
            Logger.getLogger(Util.class
                    .getName()).log(Level.SEVERE, null, ex);
            return -1;
        }
    }

    public String getIssuerDN(KeyStore keystore, String keypair_name) {
        /*
        Метода getIssuer (String keypair_name) треба да врати податке о издавачу сертификата
        који је у локалном keystore-у сачуван под алиасом keypair_name.
         */
        try {
            keystore = init(keystore);
            X509Certificate certificate = (X509Certificate) keystore.getCertificate(keypair_name);
            String issuerDN = certificate.getIssuerDN().toString();
            return issuerDN;

        } catch (KeyStoreException ex) {
            Logger.getLogger(Util.class
                    .getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public String getIssuerPublicKeyAlg(KeyStore keystore, String keypair_name) {
        /*
        Метода getIssuerPуblicKeyAlgorithm (String keypair_name) треба да врати податке о
        алгоритму који је коришћен за генерисање пара кључева сертификата који је у локалном
        keystore-у сачуван под алиасом keypair_name.
         */
        try {
            keystore = init(keystore);
            ProtectionParameter protection = new KeyStore.PasswordProtection(KS_PASSWORD.toCharArray());
            PrivateKeyEntry entry = (PrivateKeyEntry) keystore.getEntry(keypair_name, protection);
            String keyAlgorithm = entry.getPrivateKey().getAlgorithm();
            return keyAlgorithm;

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException ex) {
            Logger.getLogger(Util.class
                    .getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public boolean generateCSR(KeyStore keystore, String keypair_name) {
        /*
        Метода generateCSR(String keypair_name) треба да генерише захтев за потписивање
        сертификата (CSR) који је у локалном keystore-у сачуван под алиасом keypair_name.
        Повратна вредност методе означава успешност операције, false у случају грешке.
         */
        try {
            keystore = init(keystore);
            ProtectionParameter protection = new KeyStore.PasswordProtection(KS_PASSWORD.toCharArray());
            X509Certificate certificate = (X509Certificate) keystore.getCertificate(keypair_name);
            myCode.setCurrentSigningCertificate(certificate);
            PublicKey publickey = certificate.getPublicKey();
            PrivateKeyEntry privatekey = (PrivateKeyEntry) keystore.getEntry(keypair_name, protection);
            String sigAlg = certificate.getSigAlgName();
            X500Principal principal = certificate.getSubjectX500Principal();
            // Request saved under Util
            csrRequest = new PKCS10CertificationRequest(sigAlg, principal, publickey, null, privatekey.getPrivateKey());
            csrRequestAlias = keypair_name;
            return true;

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException ex) {
            Logger.getLogger(Util.class
                    .getName()).log(Level.SEVERE, null, ex);
            return false;

        } catch (NoSuchProviderException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(Util.class
                    .getName()).log(Level.SEVERE, null, ex);
            return true;
        }
    }

    public boolean signCSR(KeyStore keystore, X509Certificate certificateToSign, String issuer, String algorithm) {
        /*
        Метода signCertificate(String issuer, String algorithm) треба да потпише алгоритмом
        algorithm тренутно селектовани сертификат на графичком корисничком интерфејсу
        приватним кључем сертификата који је у локалном keystore-у сачуван под алиасом issuer.
        Повратна вредност методе означава успешност операције, false у случају грешке.
         */
        try {
            keystore = init(keystore);

            ProtectionParameter protection = new KeyStore.PasswordProtection(KS_PASSWORD.toCharArray());

            PrivateKeyEntry CAentry = (PrivateKeyEntry) keystore.getEntry(issuer, protection);
            X509Certificate CAcert = (X509Certificate) keystore.getCertificate(issuer);
            AsymmetricKeyParameter CAprivKeyParam = PrivateKeyFactory.createKey(CAentry.getPrivateKey().getEncoded());
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(certificateToSign.getPublicKey().getEncoded());

            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

            X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
                    new X500Name(CAcert.getSubjectDN().toString()),
                    certificateToSign.getSerialNumber(),
                    certificateToSign.getNotBefore(),
                    certificateToSign.getNotAfter(),
                    csrRequest.getCertificationRequestInfo().getSubject(),
                    subjectPublicKeyInfo
            );

            CertificateUtil CertUtil = new CertificateUtil();

            // Extensions 
            CertUtil.setCertificatePolicies_SIGNING(myCertificateGenerator, certificateToSign);
            CertUtil.setIssuerAlternativeNames_SIGNING(myCertificateGenerator, CAcert);
            CertUtil.setBasicConstraints_SIGNING(myCertificateGenerator, certificateToSign);

            ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(CAprivKeyParam);
            X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
            org.bouncycastle.asn1.x509.Certificate eeX509CertificateStructure = holder.toASN1Structure();
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

            // Read Certificate
            try (InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded())) {
                X509Certificate newCertificate = (X509Certificate) cf.generateCertificate(is1);
                PrivateKey subjectPrivateKey = ((PrivateKeyEntry) keystore.getEntry(csrRequestAlias, protection)).getPrivateKey();
                Certificate[] issuerChain = keystore.getCertificateChain(issuer);
                Certificate[] newCertificateChain = new Certificate[issuerChain.length + 1];
                newCertificateChain[0] = newCertificate;
                for (int i = 0; i < issuerChain.length; i++) {
                    newCertificateChain[i + 1] = issuerChain[i];
                }
                // Remove old
                keystore.deleteEntry(csrRequestAlias);
                // Insert new
                keystore.setKeyEntry(csrRequestAlias, subjectPrivateKey, KS_PASSWORD.toCharArray(), newCertificateChain);
                keystore.store(new FileOutputStream(KS_FILE_PATH), KS_PASSWORD.toCharArray());

            } catch (Exception e) {
                throw new CertificateException("Failed at InputStream creation.");
            }
            return true;
        } catch (NoSuchAlgorithmException | KeyStoreException | OperatorCreationException | UnrecoverableEntryException | CertificateException | IOException | NoSuchProviderException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }

    public boolean exportCertificate(KeyStore keystore, File file, int encoding) {
        /*
        Метода exportCertificate(File file, int encoding) треба да у фајл file (екстензије .cer) извезе
        постојећи сертификат тренутно селектован на графичком корисничком интерфејсу и
        кодира га на начин назначен вредношћу параметра encoding (0 за DER, 1 за PEM).
        Повратна вредност методе означава успешност операције, false у случају грешке.
         */
        try {
            keystore = init(keystore);
            Certificate[] chain = keystore.getCertificateChain(loadedKeyPair); // chain = { CertificateToExport, ... }
            // Remove previous .cer file
            if (new File(file.getAbsolutePath() + ".cer").exists()) {
                (new File(file.getAbsolutePath() + ".cer")).delete();
            }
            if (encoding == 1) {
                PEMWriter pemWriter = new PEMWriter(new FileWriter(file.getAbsolutePath() + ".cer"));
                pemWriter.writeObject(chain[0]);
                pemWriter.flush();
                pemWriter.close();
            } else {
                FileOutputStream fos = new FileOutputStream(file.getAbsolutePath() + ".cer");
                DEROutputStream dos = new DEROutputStream(fos);
                ASN1InputStream asn1inputStream = new ASN1InputStream(new ByteArrayInputStream(chain[0].getEncoded()));
                dos.writeObject(asn1inputStream.readObject());
                dos.flush();
                fos.flush();
                dos.close();
                fos.close();
            }
            return true;
        } catch (IOException | KeyStoreException | CertificateEncodingException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }

    public boolean importCertificate(KeyStore keystore, File file, String alias) {
        /*
        Метода importCertificate(File file, String keypair_name) треба да из фајла file (екстензије .cer)
        учита постојећи сертификат и сачува га у локални keystore под алиасом keypair_name.
        Повратна вредност методе означава успешност операције, false у случају грешке.
         */
        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            FileInputStream is = new FileInputStream(file.getAbsolutePath());
            X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keystore = init(keystore);
            PrivateKey tempPrivateKey = keyGen.generateKeyPair().getPrivate();
            keystore.setKeyEntry(alias, tempPrivateKey, KS_PASSWORD.toCharArray(), new Certificate[]{cer});
            keystore.store(new FileOutputStream(KS_FILE_PATH), KS_PASSWORD.toCharArray());
            return true;
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }

    }

}
