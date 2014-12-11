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

package groupsignature.signature;

import java.math.BigInteger;

import groupsignature.elliptic.ECPoint;

public class Signature {
	
	private ECPoint E0;
	private ECPoint E1;
	private ECPoint E2;
	private BigInteger ACOM;
	private BigInteger BCOM;
	private BigInteger c;
	private BigInteger Tx;
	private BigInteger Ts;
	private BigInteger TePrime;
	private BigInteger Tt;
	private BigInteger TE;
	private Integer index;
	
	public Signature(ECPoint E0, ECPoint E1, ECPoint E2,BigInteger ACOM,BigInteger BCOM,BigInteger c,BigInteger Tx,BigInteger Ts,BigInteger TePrime,BigInteger Tt,BigInteger TE,Integer index){
		this.E0 = E0;
		this.E1 = E1;
		this.E2 = E2;
		this.ACOM = ACOM;
		this.BCOM = BCOM;
		this.c = c;
		this.Tx = Tx;
		this.Ts = Ts;
		this.TePrime = TePrime;
		this.Tt = Tt;
		this.TE = TE;
		this.index = index;
	}
	
	public ECPoint getE0(){
		return this.E0;
	}
	
	public ECPoint getE1() {
		return E1;
	}

	public ECPoint getE2() {
		return E2;
	}

	public BigInteger getACOM() {
		return ACOM;
	}

	public BigInteger getBCOM() {
		return BCOM;
	}

	public BigInteger getC() {
		return c;
	}

	public BigInteger getTx() {
		return Tx;
	}

	public BigInteger getTs() {
		return Ts;
	}

	public BigInteger getTePrime() {
		return TePrime;
	}

	public BigInteger getTt() {
		return Tt;
	}

	public BigInteger getTE() {
		return TE;
	}

	public Integer getindex(){
		return index;
	}
	
}
