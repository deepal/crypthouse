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

public class Opk {
	
	private BigInteger q;
	private ECPoint G;
	private ECPoint H1;
	private ECPoint H2;
	
	public Opk(BigInteger q, ECPoint G, ECPoint H1, ECPoint H2){
		this.q = q;
		this.G = G;
		this.H1 = H1;
		this.H2 = H2;
	}
	
	public BigInteger getOrder(){
		return this.q;
	}
	
	public ECPoint getGenerator(){
		return this.G;
	}
	
	public ECPoint getH1(){
		return this.H1;
	}
	
	public ECPoint getH2(){
		return this.H2;
	}
	
}
