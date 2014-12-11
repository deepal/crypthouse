/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package vehiclesc;

import groupsignature.client.User;
import groupsignature.server.IssuingManager;
import groupsignature.server.OpeningManager;
import groupsignature.server.RevocationManager;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 *
 * @author Deepal
 */

public class VehicleSC {
    
    public VehicleSC(){
        Scanner sc = new Scanner(System.in);
	
        RevocationManager revoc = new RevocationManager();          
        IssuingManager issue = new IssuingManager(revoc);
        OpeningManager open = new OpeningManager(issue, revoc);
        
        Vehicle car1 = new Vehicle("Car1", issue, open, revoc);
        Vehicle car2 = new Vehicle("Car2", issue, open, revoc);
        Vehicle car3 = new Vehicle("Car3", issue, open, revoc);
        Vehicle car4 = new Vehicle("Car4", issue, open, revoc);
        
        car1.join();
        car2.join();
        car3.join();
        car4.join();
        
        ArrayList<Vehicle> vehicles = new ArrayList<Vehicle>();
        vehicles.add(car1);
        vehicles.add(car2);
        vehicles.add(car3);
        vehicles.add(car4);
        
        SignedMessage sMsg1 = car1.broadcastMessage("Accident at 243234");
        System.out.println("Message is sent by "+car1.getPseudo());
        this.verifyMessage(sMsg1, vehicles);
        System.out.println("-------------------------------------------------\n");
        
        SignedMessage sMsg2 = car2.broadcastMessage("Slowing down...");
        System.out.println("Message is sent by "+car2.getPseudo());
        this.verifyMessage(sMsg2, vehicles);
        System.out.println("-------------------------------------------------\n");
        
        SignedMessage sMsg3 = car3.broadcastMessage("Danger ahead");
        System.out.println("Message is sent by "+car3.getPseudo());
        this.verifyMessage(sMsg3, vehicles);
        System.out.println("-------------------------------------------------\n");
        
        SignedMessage sMsg4 = car4.broadcastMessage("Slipery road ahead");
        System.out.println("Message is sent by "+car4.getPseudo());
        this.verifyMessage(sMsg4, vehicles);
        System.out.println("-------------------------------------------------\n");
    }
    
    public static void main(String[] args) {
        new VehicleSC();
    }
    
    public void verifyMessage(SignedMessage sMsg, ArrayList<Vehicle> cars){
        for(int i=0;i<cars.size();i++){
            Vehicle current = cars.get(i);
            if(current.verifiyMessage(sMsg)){
                System.out.println("Message verified by "+current.getPseudo()+": "+sMsg.message);
            }
            else{
                System.out.println("Message verification failed at "+current.getPseudo());
            }
        }
    }
    
}
