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

public class Ipk {
	
	private BigInteger n;
	private BigInteger a0;
	private BigInteger a1;
	private BigInteger a2;
	
	public Ipk(BigInteger n, BigInteger a0, BigInteger a1, BigInteger a2){
		this.n = n;
		this.a0 = a0;
		this.a1 = a1;
		this.a2 = a2;
	}
	
	public BigInteger getn(){
		return this.n;
	}
	
	public BigInteger geta0(){
		return this.a0;
	}
	
	public BigInteger geta1(){
		return this.a1;
	}	
	
	public BigInteger geta2(){
		return this.a2;
	}	
	
}
