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

import java.math.BigInteger;
import java.util.Iterator;
import java.util.Random;
import java.util.HashMap;

import groupsignature.elliptic.ECPoint;
import groupsignature.keys.*;
import groupsignature.utils.Constants;
import groupsignature.utils.Utils;

public class IssuingManager {

	private Ipk ipk;
	private Isk isk;
	private RevocationManager revoc;
	private int nbuser;
	private HashMap<String,Mpk> users = new HashMap<String,Mpk>();
	
	public IssuingManager(RevocationManager revoc){
		//System.out.println("\n---------------Setup Issuing Manager--------------");
		long start = System.currentTimeMillis();
		Utils util = new Utils();
		this.setRevocationManager(revoc);
		// Randomly choose safe primes  
		BigInteger p1 = util.getSafePrime(Constants.Kn/2);
		BigInteger p2 = util.getSafePrime(Constants.Kn/2);
		// Compute n = p1 * p2 
		BigInteger n = p1.multiply(p2);
		// Randomly choose quadratic residues
		BigInteger a0 = util.getRandomQuadraticResidue(n);
		BigInteger a1 = util.getRandomQuadraticResidue(n);
		BigInteger a2 = util.getRandomQuadraticResidue(n);
		this.ipk = new Ipk(n,a0,a1,a2);
		this.isk = new Isk(p1,p2);
		this.nbuser = 0;
		String print = "\nIpk:\nn = "+this.getIpk().getn()+"\na0 = "+this.getIpk().geta0()+"\na1 = "+this.getIpk().geta1()+"\na2 = "+this.getIpk().geta2()+"\n\nIsk:\np1 = "+this.getIsk().getp1()+"\np2 = "+this.getIsk().getp2()+"\n\nNumber of users = "+this.getNbUsers()+"\nID-List = {/}";
		long end = System.currentTimeMillis();
		//System.out.println("Execution time was "+(end-start)+" ms.");
		//System.out.println(print+"\n\n---------------DONE--------------");
	}
	
	private void setRevocationManager(RevocationManager revoc) {
		this.revoc = revoc;
	}

	private RevocationManager getRevocationManager(){
		return this.revoc;
	}
	
	public HashMap<String,Mpk> getMembersList(){
		return this.users;
	}
	
	public Ipk getIpk(){
		return this.ipk;
	}
	
	private Isk getIsk(){
		return this.isk;
	}
	
	private int getNbUsers(){
		return this.nbuser;
	}
	
	private void setNbUsers(int nbUsers){
		this.nbuser = nbUsers;
	}
	
	// JOIN protocol
	public BigInteger getJoinXSecond() {
		// Randomly choose x"
		BigInteger xSecond = new BigInteger(Constants.lam-1,new Random());
		//System.out.println("I: x'' = "+xSecond);
		return xSecond;
	}
	
	public Mpk getCertificate(String pseudo, BigInteger APrime, ECPoint h) {
		// Randomly choose primes e and e' like 
		Boolean search = true;
		BigInteger ePrime;
		BigInteger e;
		do{
			ePrime = new BigInteger(Constants.KePrime,Constants.certainty,new Random());
			//System.out.println(ePrime);
			e = ePrime.add(Constants.expKe);
			//System.out.println(e);
			if(e.isProbablePrime(Constants.certainty)){
				search = false;
			}
		}while(search);
		//System.out.println("I: e' = "+ePrime);
		// Compute A
		BigInteger A = this.computeA(APrime,e);
		//System.out.println("I: A = "+A);
		BigInteger B = this.getRevocationManager().computeB(ePrime);
		Mpk mpk = new Mpk(A, ePrime, B, h);
		this.setNbUsers(this.getNbUsers()+1);
		this.getMembersList().put(pseudo,mpk);
		//System.out.println("I: Protocol OK => Add to list:\n\tIndex = "+ this.getNbUsers()+"\tPseudo = "+ pseudo+ "\t(A, e', B, h)");
		return mpk;
	}

	private BigInteger computeA(BigInteger aPrime, BigInteger e) {
		// Compute A = (a0*A')^(1/e) mod n
		// Euler function on n:
		BigInteger phiN = (this.getIsk().getp1().subtract(BigInteger.ONE)).multiply((this.getIsk().getp2().subtract(BigInteger.ONE)));
		// Compute 1/e
		BigInteger eInv = e.modInverse(phiN);
		BigInteger A = (aPrime.multiply(this.getIpk().geta0())).modPow(eInv,this.getIpk().getn());
		return A;
	}
	
	@SuppressWarnings("unchecked")
	public void printMemberList(){
		//System.out.println("----- Members list ------\nPseudo\t\th(x,y)");
		Iterator it = this.users.keySet().iterator();
		while(it.hasNext()){
			String pseudo = (String) it.next();
			Mpk mpk = users.get(pseudo);
			//System.out.println("\n"+ pseudo + "\t\t" + mpk.geth().getx() + "\n\t\t" + mpk.geth().gety()); 
		}
	}
}
