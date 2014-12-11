/*
 * schonfeld.david@gmail.com - Java implementation of a group signature scheme
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

package groupsignature.server;

import groupsignature.keys.*;
import groupsignature.signature.RevocationCertificate;
import groupsignature.utils.Constants;
import groupsignature.utils.Utils;

import java.math.BigInteger;
import java.util.HashMap;

public class RevocationManager {
	
	private Rpk rpk;
	private Rsk rsk;
	private HashMap<Integer,RevocationCertificate> revocList = new HashMap<Integer,RevocationCertificate>();
	private Integer index;
	
	public RevocationManager(){
		//System.out.println("\n---------------Setup RevocationManager--------------");
		long start = System.currentTimeMillis();
		Utils util = new Utils();
		BigInteger l1 = util.getSafePrime(Constants.Kn/2);
		BigInteger l2 = util.getSafePrime(Constants.Kn/2);
		BigInteger l = l1.multiply(l2);
		BigInteger b = util.getRandomQuadraticResidue(l);
		BigInteger w = util.getRandomQuadraticResidue(l);
		this.rpk = new Rpk(l,b,w);
		this.rsk = new Rsk(l1,l2);
		this.index = 0;
		String print = "\nRpk:\nl = "+l+"\nb = "+b+"\nw = "+w+"\n\nRsk:\nl1 = "+l1+"\nl2 = "+l2+"\n\nRevocation-List = {/}";
		long end = System.currentTimeMillis();
		//System.out.println("Execution time was "+(end-start)+" ms.");
		//System.out.println(print+"\n\n---------------DONE--------------");
	}
	
	public Rpk getRpk(){
		return this.rpk;
	}

	private Rsk getRsk(){
		return this.rsk;
	}
	
	private HashMap<Integer,RevocationCertificate> getRevocationList(){
		return this.revocList;
	}
	
	// JOIN PROTOCOL
	public BigInteger computeB(BigInteger ePrime) {
		// Compute B = b^(1/e') mod l
		// Euler function on l:
		BigInteger phiL = (this.getRsk().getl1().subtract(BigInteger.ONE)).multiply((this.getRsk().getl2().subtract(BigInteger.ONE)));
		// Compute 1/e'
		if(ePrime.isProbablePrime(Constants.certainty)){
			//System.out.println("R: e' is prime");
		}
		BigInteger eInv = ePrime.modInverse(phiL);
		BigInteger B = this.getRpk().getb().modPow(eInv,this.getRpk().getl());
		//System.out.println("R: B = "+B);
		return B;
	}
	
	// USER REVOCATION PROTOCOL
	public void revokeUser(Mpk mpk){
		//System.out.println("\n---------------User Revocation Process--------------");
		long start = System.currentTimeMillis();
		// Compute b' = b^(1/e) mod l
		BigInteger bOld = this.getRpk().getb();
		BigInteger phiL = (this.getRsk().getl1().subtract(BigInteger.ONE)).multiply((this.getRsk().getl2().subtract(BigInteger.ONE)));
		BigInteger eInv = mpk.getEPrime().modInverse(phiL);
		BigInteger bNew = this.getRpk().getb().modPow(eInv,this.getRpk().getl());
		RevocationCertificate revocCertif = new RevocationCertificate(mpk, rpk);
		this.getRpk().updateB(bNew);
		this.index++;
		this.getRevocationList().put(index,revocCertif);
		//System.out.println("Old b = "+ bOld+"\nNew b = "+this.getRpk().getb()+"\nAdd (mpk,rpk) to revocation list");
		long end = System.currentTimeMillis();
		//System.out.println("Execution time was "+(end-start)+" ms.");
		//System.out.println("\n---------------DONE--------------");
	}
	
	public RevocationCertificate getCertificate(Integer index){
		return this.revocList.get(index);
	}
	
	public Integer getCurrentIndex(){
		return this.index;
	}

	public BigInteger getNewCertificat(Mpk mpk, RevocationCertificate certif) {
		BigInteger phiL = (this.getRsk().getl1().subtract(BigInteger.ONE)).multiply((this.getRsk().getl2().subtract(BigInteger.ONE)));
		// Compute Alpha and Beta
		BigInteger alpha = certif.getMpk().getEPrime().multiply(new BigInteger("3")).modInverse(phiL);
		BigInteger beta = mpk.getEPrime().multiply(new BigInteger("3")).modInverse(phiL).multiply(Constants.TWO);
		// Update public key
		BigInteger B = (mpk.getB().modPow(alpha,rpk.getl()).multiply(certif.getRpk().getb().modPow(beta,rpk.getl()))).mod(rpk.getl());
		return B;
	}
	
}
