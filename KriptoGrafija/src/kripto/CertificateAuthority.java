package kripto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CRLReason;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 *
 * @author Peasant
 */
public class CertificateAuthority {

    private  X509Certificate        certificationAuthority;
    private  KeyPair                certificateAuthorityKeyPair;
    private  BouncyCastleProvider   providerBC;
    private  String                 CANameInFormat = "C=CA,O=CA";

    public CertificateAuthority(BouncyCastleProvider provider)
    {
        this.providerBC = provider;
        Security.addProvider(providerBC);

        if (!Files.exists(new File(GUI.hashedUserList.getParent() + File.separatorChar + "CA.cer").toPath(), LinkOption.NOFOLLOW_LINKS))
        {
            try
            {
                KeyPairGenerator keyGenCA = KeyPairGenerator.getInstance("RSA");
                keyGenCA.initialize(3072);

                certificateAuthorityKeyPair = keyGenCA.generateKeyPair();

                certificationAuthority = selfSign(certificateAuthorityKeyPair, CANameInFormat);
                Encryption.writeKey("CA", "password", certificateAuthorityKeyPair);
            }
            catch (IOException | CertificateException | OperatorCreationException e) { e.printStackTrace();} catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(CertificateAuthority.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else
        {
            try {
                certificationAuthority = retrieveCertificate("CA");
                certificateAuthorityKeyPair = new KeyPair(certificationAuthority.getPublicKey(), Encryption.readKey("CA", "password"));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

    }

    private X509Certificate selfSign(KeyPair keyPair, String name) throws OperatorCreationException, CertificateException, CertIOException
    {
        long currentTimeMili = System.currentTimeMillis();

        Date certificateStartingDate = new Date(currentTimeMili);

        Calendar expiryCalculator = Calendar.getInstance();
        expiryCalculator.setTime(certificateStartingDate);
        expiryCalculator.add(Calendar.YEAR,3);
        Date certificateExpirationDate = expiryCalculator.getTime();

        X500Name authorityName = new X500Name(name);

        ContentSigner signer = new JcaContentSignerBuilder("SHA512WithRSA").build(certificateAuthorityKeyPair.getPrivate());

        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(authorityName,
                new BigInteger(Long.toString(currentTimeMili)),
                certificateStartingDate,
                certificateExpirationDate,
                authorityName,
                keyPair.getPublic());

        BasicConstraints bConstraints = new BasicConstraints(true);

        certificateBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"),true,bConstraints);

        return new JcaX509CertificateConverter().setProvider(providerBC).getCertificate(certificateBuilder.build(signer));
    }

    public X509Certificate createSignedUserCertificate(String userName, PublicKey userPublicKey) throws OperatorCreationException, CertificateException
    {
        Security.addProvider(providerBC);

        long currentTimeMili = System.currentTimeMillis();

        Date certificateStartingDate = new Date(currentTimeMili);

        Calendar expiryCalculator = Calendar.getInstance();
        expiryCalculator.setTime(certificateStartingDate);
        expiryCalculator.add(Calendar.YEAR,1);
        Date certificateExpirationDate = expiryCalculator.getTime();


        ContentSigner signer = new JcaContentSignerBuilder("SHA512WithRSA").build(certificateAuthorityKeyPair.getPrivate());

        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(new X500Name(CANameInFormat),
                new BigInteger(Long.toString(currentTimeMili)),
                certificateStartingDate,
                certificateExpirationDate,
                new X500Name(userName), userPublicKey);

        BasicConstraints bConstraints = new BasicConstraints(false);

        return new JcaX509CertificateConverter().setProvider(providerBC).getCertificate(certificateBuilder.build(signer));
    }

    public X509Certificate retrieveCertificate(String userName)
    {
        try(FileInputStream fis = new FileInputStream(GUI.hashedUserList.getParent()  + File.separatorChar + userName + "Certificate" + File.separatorChar + userName + ".cer");)
        {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            X509Certificate userCertificate = (X509Certificate) certificateFactory.generateCertificate(fis);

            return userCertificate;

        } catch (IOException | CertificateException ex) {
            Logger.getLogger(CertificateAuthority.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    public X509CRL generateCRLlist(X509Certificate ca, PrivateKey caPrivateKey, X509Certificate... revoked) throws Exception
    {
        X509v2CRLBuilder builderCRL = new X509v2CRLBuilder(new X500Name(ca.getSubjectDN().getName()), new Date());

        for(X509Certificate certificate : revoked)
            builderCRL.addCRLEntry(certificate.getSerialNumber(), new Date(), CRLReason.PRIVILEGE_WITHDRAWN.ordinal());

        File crlLocation = new File(GUI.hashedUserList.getParent()+File.separatorChar+"Revoked.crl");

        if (Files.exists(crlLocation.toPath(), LinkOption.NOFOLLOW_LINKS))
        {
            try(FileInputStream input = new FileInputStream(crlLocation);)
            {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509CRL crl = (X509CRL) cf.generateCRL(input);

                Set revokedCertificates = crl.getRevokedCertificates();

                if(revokedCertificates != null && !revokedCertificates.isEmpty())
                {
                    Iterator traveler = revokedCertificates.iterator();

                    while(traveler.hasNext())
                    {
                        X509CRLEntry single = (X509CRLEntry) traveler.next();
                        builderCRL.addCRLEntry(single.getSerialNumber(), single.getRevocationDate(), CRLReason.UNSPECIFIED.ordinal());
                    }
                }
            } catch(Exception ex){
                ex.printStackTrace();
            }
        }


        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA512WithRSAEncryption");
        contentSignerBuilder.setProvider(providerBC);
        X509CRLHolder crlHolder = builderCRL.build(contentSignerBuilder.build(caPrivateKey));
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        converter.setProvider(providerBC);

        return converter.getCRL(crlHolder);
    }

    public void writeCRL(X509CRL crlList)
    {
        try (PrintWriter printCRL = new PrintWriter(GUI.hashedUserList.getPath() + File.separatorChar + "Revoked.crl");
             JcaPEMWriter pemWriter = new JcaPEMWriter(printCRL)) {
            pemWriter.writeObject(crlList);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static void IsValidCertificate(X509Certificate certificate)
    {
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException ex) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "Certificate of message recipient is no longer valid" + " !", ButtonType.OK);
            alert.showAndWait();
        }
    }
}
