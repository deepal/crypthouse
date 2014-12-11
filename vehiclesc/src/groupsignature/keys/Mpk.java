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

package groupsignature.keys;

import java.math.BigInteger;

import groupsignature.elliptic.ECPoint;

public class Mpk {

	private BigInteger A;
	private BigInteger eprime;
	private BigInteger B;
	private ECPoint h;
	
	public Mpk(BigInteger A, BigInteger eprime, BigInteger B,ECPoint h){
		this.A = A;
		this.eprime = eprime;
		this.B = B;
		this.h = h;
	}
	
	public BigInteger getA(){
		return this.A;
	}
	
	public BigInteger getEPrime(){
		return this.eprime;
	}

	public void setB(BigInteger newB){
		this.B = newB;
	}
	
	public BigInteger getB(){
		return this.B;
	}

	public ECPoint geth(){
		return this.h;
	}
}
