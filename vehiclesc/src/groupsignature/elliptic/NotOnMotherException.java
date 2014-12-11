/**
 * From http://code.google.com/p/workshop-2011/source/checkout
 */

package groupsignature.elliptic;

public class NotOnMotherException extends Exception{

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private ECPoint sender;

    public NotOnMotherException(ECPoint sender){
	this.sender = sender;
    }

    public String getErrorString(){
	return "NotOnMother";
    }

    public ECPoint getSource(){
	return sender;
    }
}
