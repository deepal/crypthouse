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

public class Isk {

	private BigInteger p1;
	private BigInteger p2;
	
	public Isk(BigInteger p1, BigInteger p2){
		this.p1 = p1;
		this.p2 = p2;
	}
	
	public BigInteger getp1(){
		return this.p1;
	}
	
	public BigInteger getp2(){
		return this.p2;
	}
	
}
