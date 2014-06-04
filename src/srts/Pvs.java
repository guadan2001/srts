package srts;

import java.security.MessageDigest;

import srts.elements.Ck;
import srts.elements.Mcs;
import srts.elements.Pk;
import srts.elements.Sk;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class Pvs {
	
	public Pairing pairing;
	
	public final static int COMMIT_PE_BASED = 0;
	public final static int COMMIT_HA_BASED = 1;
	
	public Pvs()
	{
		pairing = Utils.getPairing();
	}
	
	public void keygen(String pkFile, String skFile, String gFile, String yFile) throws Exception
	{
		Pk pk = new Pk();
		Sk sk = new Sk();
		Element g = pairing.getG2().newRandomElement();
		Element x = pairing.getZr().newRandomElement();
		Element y = pairing.getZr().newRandomElement();
		Element g_tick = pairing.getG1().newRandomElement();
		Element h_tick = pairing.getG1().newRandomElement();
		
		pk.pk = g.duplicate();
		pk.pk.powZn(x);
		pk.ck = new Ck();
		pk.ck.g_tick = g_tick.duplicate();
		pk.ck.h_tick = h_tick.duplicate();
		
		sk.sk = x.duplicate();
		sk.ck = new Ck();
		sk.ck.g_tick = g_tick.duplicate();
		sk.ck.h_tick = h_tick.duplicate();
		
		byte[] pkByte = Utils.serializePk(pk);
		byte[] skByte = Utils.serializeSk(sk);
		byte[] gByte = Utils.serializeG(g);
		byte[] yByte = Utils.serializeZrElement(y);
		Utils.spitFile(pkFile, pkByte);
		Utils.spitFile(skFile, skByte);
		Utils.spitFile(gFile, gByte);
		Utils.spitFile(yFile, yByte);
	}
	
	public void sign(String skFile, String yFile, String mFile, String deltaFile, int commitAlgo) throws Exception
	{
		byte[] skByte = srts.Utils.suckFile(skFile);
		byte[] yByte = Utils.suckFile(yFile);
		byte[] mByte = srts.Utils.suckFile(mFile);

		Sk sk = Utils.unserializeSk(skByte);
		Element y = Utils.unserializeZrElement(yByte);
		Element com = pairing.getG1().newElement();
		com = commit(sk.ck, y, mByte, commitAlgo);
		Element s = pairing.getG1().newElement();
		s = sig(sk.sk, com);
		
		byte[] deltaByte = Utils.serializeDelta(s);
		Utils.spitFile(deltaFile, deltaByte);
	}
	
	public boolean verify(String pkFile, String gFile, String yFile, String mFile, String deltaFile, int commitAlgo) throws Exception
	{
		byte[] pkByte = Utils.suckFile(pkFile);
		byte[] gByte = Utils.suckFile(gFile);
		byte[] yByte = Utils.suckFile(yFile);
		byte[] mByte = Utils.suckFile(mFile);
		byte[] deltaByte = Utils.suckFile(deltaFile);
		
		Pk pk = Utils.unserializePk(pkByte);
		Element g = Utils.unserializeG(gByte);
		Element y = Utils.unserializeZrElement(yByte);
		Element delta = Utils.unserializeDelta(deltaByte);
		
		Element com = pairing.getG1().newElement();
		com = commit(pk.ck, y, mByte, commitAlgo);
			
		return ver(pk.pk, com, g, delta);
	}
	
	public void priSign(String pkFile, String skFile, String yFile, String mFile, String mcsFile, int commitAlgo) throws Exception
	{
		byte[] pkByte = Utils.suckFile(pkFile);
		byte[] skByte = Utils.suckFile(skFile);
		byte[] yByte = Utils.suckFile(yFile);
		byte[] mByte = Utils.suckFile(mFile);
		
		Pk pk = Utils.unserializePk(pkByte);
		Sk sk = Utils.unserializeSk(skByte);
		Element y = Utils.unserializeZrElement(yByte);
		
		Element com = commit(pk.ck, y, mByte, commitAlgo);
		Element s = sig(sk.sk, com);
		
		Mcs mcs = new Mcs();
		mcs.mc = com.duplicate();
		mcs.delta = s.duplicate();
		
		byte[] mcsByte = Utils.serializeMcs(mcs);
		Utils.spitFile(mcsFile, mcsByte);
	}
	
	public boolean priVerify(String pkFile, String gFile, String mcsFile) throws Exception
	{
		byte[] pkByte = Utils.suckFile(pkFile);
		byte[] gByte = Utils.suckFile(gFile);
		byte[] mcsByte = Utils.suckFile(mcsFile);
		
		Pk pk = Utils.unserializePk(pkByte);
		Element g = Utils.unserializeG(gByte);
		Mcs mcs = Utils.unserializeMcs(mcsByte);

		return ver(pk.pk, mcs.mc, g, mcs.delta);
	}
	
	public boolean check(String pkFile, String yFile, String mFile, String mcsFile, int commitAlgo) throws Exception
	{
		byte[] pkByte = Utils.suckFile(pkFile);
		byte[] yByte = Utils.suckFile(yFile);
		byte[] mByte = Utils.suckFile(mFile);
		byte[] mcsByte = Utils.suckFile(mcsFile);
		
		Pk pk = Utils.unserializePk(pkByte);
		Element y = Utils.unserializeZrElement(yByte);
		Mcs mcs = Utils.unserializeMcs(mcsByte);
		
		Element com = commit(pk.ck, y, mByte, commitAlgo);
		
		if(mcs.mc.isEqual(com))
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	
	public Element sig(Element sk, Element com)
	{
		Pairing pairing = Utils.getPairing();
		Element sig = pairing.getG1().newElement();
		sig  = com.duplicate();
		sig.powZn(sk);
		return sig;
	}
	
	public Element commit(Ck ck, Element y, byte[] m, int algorithm) throws Exception
	{
		Pairing pairing = Utils.getPairing();
		
		Element commitment1 = pairing.getG1().newElement();
		Element commitment2 = pairing.getG1().newElement();
		
		if(algorithm == Pvs.COMMIT_PE_BASED)
		{
			commitment1 = ck.g_tick.duplicate();
			commitment1.powZn(pairing.getZr().newElement().setFromHash(m, 0, m.length));
			commitment2 = ck.h_tick.duplicate();
			commitment2.powZn(y);
			commitment1.mul(commitment2);
		}
		else if(algorithm == Pvs.COMMIT_HA_BASED)
		{
			commitment1.setFromHash(m, 0, m.length);
		}
		
		return commitment1;
	}
	
	public boolean ver(Element pk, Element com, Element g, Element delta)
	{
		Element temp1 = pairing.pairing(com, pk);
		Element temp2 = pairing.pairing(delta, g);
		
		if(temp1.isEqual(temp2))
		{
			return true;
		}
		else
		{
			return false;
		}
	}
}
