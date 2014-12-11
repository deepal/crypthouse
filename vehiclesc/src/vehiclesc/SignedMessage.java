/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package vehiclesc;

import groupsignature.signature.Signature;

/**
 *
 * @author Deepal
 */
public class SignedMessage {    //Signed message contains a digital signature and the message itself
    public Signature sign;
    public String message;
    
    public SignedMessage(Signature s, String msg){
        this.sign = s;
        this.message = msg;
    }
}
