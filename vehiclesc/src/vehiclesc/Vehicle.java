/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package vehiclesc;

import groupsignature.client.User;
import groupsignature.client.Verifier;
import groupsignature.server.IssuingManager;
import groupsignature.server.OpeningManager;
import groupsignature.server.RevocationManager;
import groupsignature.signature.Signature;

/**
 *
 * @author Deepal
 */
public class Vehicle extends groupsignature.client.User{    //Vehicle class inherits User functionality
    
    private Verifier verifier;  
    
    public Vehicle(String vehicleName, IssuingManager issueMan, OpeningManager openMan, RevocationManager revocMan){
        super(vehicleName, issueMan, openMan, revocMan);        
        verifier = new Verifier(issueMan, openMan, revocMan);           //create a verifier per each vehicle
    }
    
    public SignedMessage broadcastMessage(String message){
        Signature sign = this.sign(message);                    //create a message, sign and send it.
        return new SignedMessage(sign, message);
    }
    
    public boolean verifiyMessage(SignedMessage smsg){
        return verifier.verify(smsg.message, smsg.sign);        //verify the message
    }
    
}
