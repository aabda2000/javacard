package be.msec.client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;
import be.msec.client.utils.ArrayUtils;
import be.msec.client.utils.TextOperations;

import com.sun.javacard.apduio.Apdu;
import com.sun.javacard.apduio.CadT1Client;
import com.sun.javacard.apduio.TLP224Exception;
import javax.smartcardio.*;

public class Client {
    private final static byte IDENTITY_CARD_CLA = (byte) 0x80;

    private final static short SW_VERIFICATION_FAILED = 0x6300;

    private static final byte VALIDATE_PIN_INS = (byte) 0x22;
    private static final byte GET_IDENTITY_INS = (byte) 0x24;
    protected static final byte GET_CERTIFICATE_INS = (byte) 0x28;

    /**
     * @param args
     */
    public static void main(String[] args) {
        IConnection c = null;
        try {
            // Simulation:
            // c = new SimulatedConnection();

            // Real Card:
            c = new Connection();
            ((Connection) c).setTerminal(0); // depending on which cardreader
            // you use

            c.connect();

            /*
             * For more info on the use of CommandAPDU and ResponseAPDU: See http
             * ://java.sun.com/javase/6/docs/jre/api/security/smartcardio/spec /index.html
             */

            // 1. Select applet
            CommandAPDU a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
                    new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00 });
            ResponseAPDU r = c.transmit(a);
            if (r.getSW() != 0x9000)
                throw new Exception("Applet selection failed");

            // 2. Send PIN
            a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, new byte[] { 0x01, 0x02, 0x03, 0x04 });
            r = c.transmit(a);

            if (r.getSW() == SW_VERIFICATION_FAILED)
                throw new Exception("PIN INVALID");

            System.out.println("PIN Verified");

            // 3. Get Identity File
            byte[] identBytes = getIdentityFile(c);
            String identite = TextOperations.hexDump(identBytes);
            System.out.println(identite);
            System.out.println(TextOperations.hexToAscii(identite));
           
            //4. Request certificate
            byte[] certBytes = getCertificate(c);
            System.out.println("Certificate: "+TextOperations.hexDump(certBytes));
            CertificateFactory certFac = CertificateFactory.getInstance("X.509");
            InputStream is = new ByteArrayInputStream(certBytes);
            X509Certificate cert = (X509Certificate) certFac.generateCertificate(is);
            System.out.println(cert.getPublicKey());
            System.out.println(cert.getSubjectX500Principal());
           
        } catch (Exception e) {
            System.err.println(e.getMessage());
        } finally {
            try {
                c.close();
            } catch (Exception e) {

            } // close the connection with the card
        }

    }

    private static byte[] getIdentityFile(IConnection c) throws Exception {
        byte[] identity = new byte[0];

        try {
            byte[] comAPDUBytes = new byte[] { IDENTITY_CARD_CLA, GET_IDENTITY_INS, 0, 0, (byte) 240 };
            CommandAPDU command = new CommandAPDU(comAPDUBytes);
            ResponseAPDU resp = c.transmit(command);
            return resp.getData();
        } catch (CardException ce) {
            throw new Exception();
        }
    }

    public static byte[] getCertificate(IConnection c) throws Exception {
        try {
            byte count = 0;
            byte[] certificate = new byte[0];
            ResponseAPDU apdu;
            do {
                apdu = sendGetCertificateCommand(count, c);
                if (apdu.getSW() == 36864)
                    certificate = ArrayUtils.concat(certificate, apdu.getData());
                count++;
            } while (apdu.getSW() != 27270 && count < 10);
            return certificate;
        } catch (CardException ce) {
            throw new Exception();
        }
    }

    private static ResponseAPDU sendGetCertificateCommand(byte count, IConnection c) throws Exception {
        byte[] comAPDUBytes = new byte[] { IDENTITY_CARD_CLA, GET_CERTIFICATE_INS, count, 0, (byte) 240 };
        CommandAPDU command = new CommandAPDU(comAPDUBytes);
        ResponseAPDU resp;

        resp = c.transmit(command);

        return resp;
    }
}
