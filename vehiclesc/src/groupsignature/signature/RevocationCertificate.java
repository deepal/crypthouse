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

import groupsignature.keys.Mpk;
import groupsignature.keys.Rpk;

public class RevocationCertificate{
	
	private Mpk mpk;
	private Rpk rpk;
	
	public RevocationCertificate(Mpk mpk, Rpk rpk){
		this.rpk = rpk;
		this.mpk = mpk;
	}
	
	public Rpk getRpk(){
		return this.rpk;
	}
	
	public Mpk getMpk(){
		return this.mpk;
	}
}
