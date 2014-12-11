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

package groupsignature.utils;

import groupsignature.utils.Constants;

import java.math.BigInteger;
import java.util.Random;

public class Utils {
	
	public BigInteger getSafePrime(int n){
		Boolean search = true;
		BigInteger p;
		do{
			p = new BigInteger(n/2,Constants.certainty,new Random()).multiply(Constants.TWO).add(Constants.ONE);
			if (p.isProbablePrime(Constants.certainty)){
				search = false;
			}
		}
		while(search);
		return p;
	}
	
	public BigInteger getRandomQuadraticResidue(BigInteger n){
		BigInteger x = new BigInteger(Constants.Kn,new Random());
		BigInteger qr = x.modPow(Constants.TWO,n);
		return qr;
	}
	
	public BigInteger getRandomBinaryString(int length){
		String string = "1";
		for(int i=0;i<length-1;i++){
			if (java.lang.Math.random()<0.5){
				string += "1";
			}
			else{
				string += "0";
			}
		}
		return new BigInteger(string);
	}
}
