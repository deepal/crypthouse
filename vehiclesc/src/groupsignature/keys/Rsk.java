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

public class Rsk {
	
	private BigInteger l1;
	private BigInteger l2;
	
	public Rsk(BigInteger l1, BigInteger l2){
		this.l1 = l1;
		this.l2 = l2;
	}
	
	public BigInteger getl1(){
		return this.l1;
	}
	
	public BigInteger getl2(){
		return this.l2;
	}
	
}
