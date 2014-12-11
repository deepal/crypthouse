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

import java.math.BigInteger;

public class Constants {
	public static final int certainty = 7;
	public static final int Kn = 1024;
	public static final int Kl = 1024;
	public static final int Ke = 504;
	public static final int KePrime = 60;
	public static final int K = 169;
	public static final int Ks = 60;
	public static final int Kc = 256;
	public static final int lam = Kn + K + Ks;
	
	public static final BigInteger ONE = new BigInteger("1");
	public static final BigInteger TWO = new BigInteger("2");
	public static final BigInteger expLam = TWO.pow(lam);
	public static final BigInteger expKe = TWO.pow(Ke);
}
