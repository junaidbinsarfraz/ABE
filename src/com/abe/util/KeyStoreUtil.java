package com.abe.util;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

import it.unisa.dia.gas.crypto.circuit.BooleanCircuit;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.params.GGHSW13MasterSecretKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.params.GGHSW13Parameters;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.params.GGHSW13PublicKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.params.GGHSW13SecretKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;

public class KeyStoreUtil {
	
	/////////////////////////////////////// Master Secret Key Starts /////////////////////////////////////////////
	
	public static void serializeMasterSecretKey(GGHSW13MasterSecretKeyParameters msk, OutputStream out) throws IOException {
        DataOutputStream dOut = new DataOutputStream(out);

        dOut.writeInt(1); // version of the serialized format
        dOut.writeInt(msk.getParameters().getN());

        serializeElement(msk.getAlpha(), dOut, msk.getParameters().getPairing());
    }

    public static GGHSW13MasterSecretKeyParameters deserializeMasterSecretKey(InputStream in, Pairing pairing) throws IOException {
        DataInputStream dIn = new DataInputStream(in);

        int version = dIn.readInt();
        if (version != 1) {
            throw new RuntimeException("Unknown key format version: " + version);
        }

        int n = dIn.readInt();//getInt();
        Element alpha = deserializeElement(dIn, pairing);

        return new GGHSW13MasterSecretKeyParameters(
                new GGHSW13Parameters(pairing, n),
                alpha
        );
    }
    
    /////////////////////////////////////// Master Secret Key Ends /////////////////////////////////////////////
	
    /////////////////////////////////////// Public Key Starts /////////////////////////////////////////////
	
    
    public static void serializePublicKey(GGHSW13PublicKeyParameters publicKey, OutputStream out) throws IOException {
    	DataOutputStream dOut = new DataOutputStream(out);
    	
    	dOut.writeInt(1); // version of the serialized format
    	dOut.writeInt(publicKey.getParameters().getN());
    	
    	serializeElement(publicKey.getH(), dOut, publicKey.getParameters().getPairing());
    	
    	int j = 0;
    	
    	try {
	    	while(publicKey.getHAt(j) != null) {
	    		j++;
	    	}
    	} catch(Exception e) {
    		// It means that it has max j values
    	}
    	
    	dOut.writeInt(j);
    	
    	for(int i = 0; i < j; i++) {
    		serializeElement(publicKey.getHAt(i), dOut, publicKey.getParameters().getPairing());
    	}
    	
    	dOut.flush();
    	
    }
    
    public static GGHSW13PublicKeyParameters deserializePublicKey(InputStream in, Pairing pairing) throws IOException {
    	DataInputStream dIn = new DataInputStream(in);

        int version = dIn.readInt();
        if (version != 1) {
            throw new RuntimeException("Unknown key format version: " + version);
        }

        int n = dIn.readInt();
        
        Element alpha = deserializeElement(dIn, pairing);
        
        int len = dIn.readInt();
        
        Element[] elems = new Element[len];
        
        for(int i = 0; i < len; i++) {
        	elems[i] = deserializeElement(dIn, pairing);
        }
        
        return new GGHSW13PublicKeyParameters(new GGHSW13Parameters(pairing, n), alpha, elems);
    }
    
    /////////////////////////////////////// Public Key Ends /////////////////////////////////////////////
    
    /////////////////////////////////////// Secret Key Starts /////////////////////////////////////////////
    
    public static void serializeSecretKey(final GGHSW13SecretKeyParameters secretKey, OutputStream out) throws IOException {
    	DataOutputStream dOut = new DataOutputStream(out);
    	
    	dOut.writeInt(1); // version of the serialized format
    	dOut.writeInt(secretKey.getParameters().getN());
    	
    	// n, circuit, keys
    	// keys : Map<Integer, Element[]>
    	
    	int minMapIndex = -1, maxMapIndex = minMapIndex;
    	
    	
    	try {
    		
    		while(secretKey.getKeyElementsAt(maxMapIndex++) != null) {
    		}
    		
    	} catch (Exception e) {
    		
    	}
    	
    	maxMapIndex -= 1;
    	
    	dOut.writeInt(minMapIndex);
    	dOut.writeInt(maxMapIndex);
    	
    	for(int i = minMapIndex; i < maxMapIndex; i++) {
    		Element[] elems = secretKey.getKeyElementsAt(i);
    		
        	dOut.writeInt(elems.length);
        	
//        	System.out.println("Size : " + elems.length);
        	
        	for(int k = 0; k < elems.length; k++) {
        		serializeElement(elems[k], dOut, secretKey.getParameters().getPairing());
        	}
    		
    	}
    	
    	dOut.flush();
    	
    }
    
    public static GGHSW13SecretKeyParameters deserializeSecretKey(InputStream in, final Pairing pairing, String bits) throws IOException {
    	DataInputStream dIn = new DataInputStream(in);

        int version = dIn.readInt();
        if (version != 1) {
            throw new RuntimeException("Unknown key format version: " + version);
        }

        int n = dIn.readInt();
        int minMapIndex = dIn.readInt();
        int maxMapIndex = dIn.readInt();
        
        Map<Integer, Element[]> keys = new HashMap<>();
        
        for(int i = minMapIndex; i < maxMapIndex; i++) {
        	
        	int elemsLength = dIn.readInt();
        	
        	Element[] elems = new Element[elemsLength];
        	
//        	System.out.println("Size : " + elems.length);
        	
        	for(int j = 0; j < elemsLength; j++) {
        		elems[j] = deserializeElement(dIn, pairing);
        	}
        	
        	keys.put(i, elems);
        }
        
        BooleanCircuit circuit = BitsUtil.generateBooleanCircuit(bits);
        
        return new GGHSW13SecretKeyParameters(new GGHSW13Parameters(pairing, n), circuit, keys);
    }
    
    /////////////////////////////////////// Secret Key Ends /////////////////////////////////////////////
	
    private static void serializeElement(Element elem, DataOutputStream dOut, Pairing pairing) throws IOException {
        dOut.writeBoolean(elem == null);
        if (elem == null) {
            return;
        }

        dOut.writeInt(pairing.getFieldIndex(elem.getField()));
        byte[] bytes = elem.toBytes();
        dOut.writeInt(bytes.length);
        dOut.write(bytes);

        // this is a workaround because it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement does not serialize the infFlag
        dOut.writeBoolean(elem instanceof CurveElement && elem.isZero());
        if (elem instanceof CurveElement && elem.isZero()) {
            throw new IOException("Infinite element detected. They should not happen.");
        }
    }
    
    private static Element deserializeElement(DataInputStream dIn, Pairing pairing) throws IOException {
    	if (dIn.readBoolean()) {
    		return null;
    	}
    	
    	int fieldIndex = dIn.readInt(); // TODO: check if this is in a sensible range
    	int length = dIn.readInt(); // TODO: check if this is in a sensible range
    	byte[] bytes = new byte[length];
    	dIn.readFully(bytes); // throws an exception if there is a premature EOF
    	Element e = pairing.getFieldAt(fieldIndex).newElementFromBytes(bytes);
    	
    	// this is a workaround because it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement does not serialize the infFlag
    	boolean instOfCurveElementAndInf = dIn.readBoolean();
    	if (instOfCurveElementAndInf) {
    		//e.setToZero(); // according to the code this simply sets the infFlag to 1
    		throw new IOException("The point is infinite. This shouldn't happen.");
    	}
    	return e;
    }
}
