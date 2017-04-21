package com.abe.main;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.abe.util.BitsUtil;
import com.abe.util.CryptoConstants;
import com.abe.util.KeyStoreUtil;

import it.unisa.dia.gas.crypto.circuit.BooleanCircuit;
import it.unisa.dia.gas.crypto.circuit.BooleanCircuit.BooleanCircuitGate;
import it.unisa.dia.gas.crypto.circuit.BooleanGate;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.engines.GGHSW13KEMEngine;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.generators.GGHSW13KeyPairGenerator;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.generators.GGHSW13ParametersGenerator;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.generators.GGHSW13SecretKeyGenerator;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.params.GGHSW13EncryptionParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.params.GGHSW13KeyPairGenerationParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.params.GGHSW13MasterSecretKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.params.GGHSW13PublicKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.params.GGHSW13SecretKeyGenerationParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.params.GGHSW13SecretKeyParameters;
import it.unisa.dia.gas.crypto.kem.cipher.engines.KEMCipher;
import it.unisa.dia.gas.crypto.kem.cipher.params.KEMCipherDecryptionParameters;
import it.unisa.dia.gas.crypto.kem.cipher.params.KEMCipherEncryptionParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.concurrent.ExecutorServiceUtils;

public class Example {
    protected KEMCipher kemCipher;
    protected AlgorithmParameterSpec iv;

    protected AsymmetricCipherKeyPair keyPair;
    
    GGHSW13MasterSecretKeyParameters newMasterSecretKey;
    GGHSW13PublicKeyParameters newPublicKey;


    public Example() throws GeneralSecurityException {
        this.kemCipher = new KEMCipher(
                Cipher.getInstance("AES/CBC/PKCS7Padding", "BC"),
                new GGHSW13KEMEngine()
        );

        // build the initialization vector.  This example is all zeros, but it
        // could be any value or generated using a random number generator.
        iv = new IvParameterSpec(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    }

    

    public AsymmetricCipherKeyPair setup(int n) {
        GGHSW13KeyPairGenerator setup = new GGHSW13KeyPairGenerator();
        setup.init(new GGHSW13KeyPairGenerationParameters(
                new SecureRandom(),
                new GGHSW13ParametersGenerator().init(
                        PairingFactory.getPairing("params/mm/ctl13/toy.properties"),
                        n).generateParameters()
        ));
        
        return (keyPair = setup.generateKeyPair());
    }


    public byte[] initEncryption(String assignment) {
        try {
            return kemCipher.init(
                    true,
                    new KEMCipherEncryptionParameters(
                            128,
                            new GGHSW13EncryptionParameters(
                                    this.newPublicKey,
                                    assignment
                            )
                    ),
                    iv
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] encrypt(String message) {
        try {
            return kemCipher.doFinal(message.getBytes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public CipherParameters keyGen(BooleanCircuit circuit) {
        GGHSW13SecretKeyGenerator keyGen = new GGHSW13SecretKeyGenerator();
        keyGen.init(new GGHSW13SecretKeyGenerationParameters(
                (this.newPublicKey),
                (this.newMasterSecretKey),
                circuit
        ));

        return keyGen.generateKey();
    }

    public byte[] decrypt(CipherParameters secretKey, byte[] encapsulation, byte[] ciphertext) {
        try {
            kemCipher.init(
                    false,
                    new KEMCipherDecryptionParameters(secretKey, encapsulation, 128),
                    iv
            );
            return kemCipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            // Setup
            int n = CryptoConstants.N;
            Example engine = new Example();
            engine.setup(n);
            
            // Here I want to store (GGHSW13PublicKeyParameters) keyPair.getPublic() and 
            // (GGHSW13MasterSecretKeyParameters) keyPair.getPrivate() in files and later to retrieve from file
            
            GGHSW13PublicKeyParameters publicKey = (GGHSW13PublicKeyParameters) engine.keyPair.getPublic();
            GGHSW13MasterSecretKeyParameters masterSecretKey = (GGHSW13MasterSecretKeyParameters) engine.keyPair.getPrivate();
            
            KeyStoreUtil.serializeMasterSecretKey(masterSecretKey, new FileOutputStream("msk.txt"));
            
            engine.newMasterSecretKey = KeyStoreUtil.deserializeMasterSecretKey(new FileInputStream("msk.txt"), masterSecretKey.getParameters().getPairing());
            
            KeyStoreUtil.serializePublicKey(publicKey, new FileOutputStream("public.txt"));
            
            engine.newPublicKey = KeyStoreUtil.deserializePublicKey(new FileInputStream("public.txt"), publicKey.getParameters().getPairing());
            
            // Encrypt
            String message = "Hello World!!!";
            byte[] encapsulation = engine.initEncryption("11011");
            byte[] ciphertext = engine.encrypt(message);
            
            BooleanCircuitGate bcg1 = BitsUtil.off(0, 1);
            
            /*BooleanCircuitGate[] bcgs = new BooleanCircuitGate[]{
                    new BooleanCircuitGate(INPUT, 0, 1),
                    new BooleanCircuitGate(INPUT, 1, 1),
                    new BooleanCircuitGate(INPUT, 2, 1),
                    new BooleanCircuitGate(INPUT, 3, 1),

                    new BooleanCircuitGate(AND, 4, 2, new int[]{0, 1}),
                    new BooleanCircuitGate(OR, 5, 2, new int[]{2, 3}),

                    new BooleanCircuitGate(AND, 6, 3, new int[]{4, 5}),
            };*/
            
            List<BooleanCircuitGate> bcgList = new ArrayList<BooleanCircuitGate>();
            
            bcgList.add(bcg1);
            bcgList.add(BitsUtil.off(1, 1));
            bcgList.add(BitsUtil.off(2, 1));
            bcgList.add(BitsUtil.off(3, 1));
            bcgList.add(BitsUtil.off(4, 1));
            /*bcgList.add(new BooleanCircuitGate(AND, 4, 2, new int[]{0, 1}));
            bcgList.add(new BooleanCircuitGate(OR, 5, 2, new int[]{2, 3}));
            bcgList.add(new BooleanCircuitGate(AND, 6, 3, new int[]{4, 5}));*/
            
            // Decrypt
            int q = CryptoConstants.Q;
            BooleanCircuit circuit = new BooleanCircuit(n, q, CryptoConstants.DEPTH, bcgList.toArray(new BooleanCircuitGate[bcgList.size()]));
            
            GGHSW13SecretKeyParameters secretKey = (GGHSW13SecretKeyParameters) engine.keyGen(circuit);
            
            for (BooleanGate gate : secretKey.getCircuit()) {
            	int index = gate.getIndex();
            	System.out.println(index);
            }
            
            KeyStoreUtil.serializeSecretKey(secretKey, new FileOutputStream("secret.txt"));
            
            GGHSW13SecretKeyParameters newSecretKey = KeyStoreUtil.deserializeSecretKey(new FileInputStream("secret.txt"), 
            		secretKey.getParameters().getPairing(), "00000");
            
            byte[] plaintext1 = engine.decrypt(secretKey, encapsulation, ciphertext);
            
            byte[] plaintext = engine.decrypt(newSecretKey, encapsulation, ciphertext);
            
            System.out.println(new String(plaintext));
            System.out.println(new String(plaintext1));
            
            // Test
//            secretKey.getKeyElementsAt(index)
            
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            ExecutorServiceUtils.shutdown();
        }
    }

}