//
//  AuthenticationPluginSwift.swift
//  authapp
//
//  Created by Mario Auernheimer on 05.10.16.
//  Copyright © 2016 Mario Auernheimer. All rights reserved.
//

import UIKit
import authenticationFramework

@objc(AuthenticationPlugin) class AuthenticationPlugin : CDVPlugin {
    
    @objc(authenticate:) func authenticate(command: CDVInvokedUrlCommand) {
        
        print("AuthPlugin :: authenticate is called")
        
        let serviceUrl = "" //insert service
        
        AuthenticationManager.sharedManager.productionConfig(false, serviceUrl: serviceUrl)
        
        if (AuthenticationManager.sharedManager.userCertificate != nil) {
            URLSession.shared.reset {
                if let samlRequest  = command.arguments[0] as? String, let idPUrl:String = command.arguments[1] as? String {
                    // Provide SAML Response for Auth via MFP
                    AuthenticationManager.sharedManager.provideSAMLResponse(samlRequest, httpMethod: HTTPMethod.get, namUrl: idPUrl) { (response, error) in
                        if error == nil {
                            let pluginResult:CDVPluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: response)
                            self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
                        }
                        else {
                            let pluginResult:CDVPluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: error.debugDescription)
                            self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
                        }
                    }
                }
                else {
                    // NAM Authentication with X509 Certificate (no SAML request needed)
                    
                    //first check if we have a valid session cookie
                    AuthenticationManager.sharedManager.authenticateNAM { (response, error) in
                        if error == nil {
                            let pluginResult:CDVPluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: response)
                            self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
                        }
                        else {
                            let pluginResult:CDVPluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: error.debugDescription)
                            self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
                        }
                    }
                }
            }
        }
        else {
            let pluginResult:CDVPluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: "User Certificate not added")
            self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
        }
    }
    
    @objc(validateSession:) func validateSession(command: CDVInvokedUrlCommand) {
        
        print("AuthPlugin :: validate session is called")
        
        //Customize these constants for your specific service
        let cookieName = command.arguments[0] as! String
        let sessionTimeInMinutes = command.arguments[1] as! Int
        var cookieRef: HTTPCookie?
        
        let cookies = HTTPCookieStorage.shared.cookies
        for cookie in cookies! { //identify correct session cookie and check expiration date
            if (cookie.name == cookieName) {
                cookieRef = cookie
                if cookie.expiresDate != nil { //compare dates if we have a expriation date
                    let expireDate = cookie.expiresDate
                    let currentDate = Date()
                    
                    if expireDate?.compare(currentDate) == ComparisonResult.orderedDescending {
                        //expire date is later than currentDate, session is still valid
                        let pluginResult: CDVPluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: true)
                        self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
                    }
                    else if expireDate?.compare(currentDate) == ComparisonResult.orderedDescending {
                        //expire date is earlier than currentDate, we have to reauthenticate
                        let pluginResult: CDVPluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: false)
                        self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
                    }else if expireDate?.compare(currentDate) == ComparisonResult.orderedSame {
                        //expire date is same with currentDate, reauthenticate
                        let pluginResult: CDVPluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: false)
                        self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
                    }
                }
                else { //if there is no valid expiration date, the expiration is set to 'session' and we have to check if the last date we tracked is longer than a given amount of time
                    let defaults = UserDefaults.standard
                    let date = defaults.object(forKey: "SessionTimeStamp") as! Date
                    let currentDate = Date()
                    
                    let minutesDiff = Calendar.current.dateComponents([.minute], from: date, to: currentDate).minute
                    print("minutesDiff \(minutesDiff) sessionTimeInMinutes: \(sessionTimeInMinutes)")
                    if (minutesDiff! > sessionTimeInMinutes) {
                        //session not valid anymore, send false
                        let pluginResult: CDVPluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: false)
                        self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
                        
                        //renew session timestamp
                        defaults.set(Date(), forKey: "SessionTimeStamp")
                    }
                    else {
                        // session is still valid, send true
                        let pluginResult: CDVPluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: true)
                        self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
                    }
                }
            }
        }
        // no session cookie found, we are not yet logged in yet and have to store the current date for next session check in user defaults
        if (cookieRef == nil) {
            let defaults = UserDefaults.standard
            defaults.set(Date(), forKey: "SessionTimeStamp")
            
            let pluginResult:CDVPluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: "NAM Session Cookie not found")
            self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
        }
    }
    
    @objc(resetSessionTimestamp:) func resetSessionTimestamp(command: CDVInvokedUrlCommand) {
        let minutesDiff = command.arguments[0] as! Int
        //get current timestamp from user defaults
        let defaults = UserDefaults.standard
        if let timestamp = defaults.object(forKey: "SessionTimeStamp") as? Date {
            //get current date and add minutesDiff, since we have to make sure the user didn`t let the screen awake and the phone signed off automatically
            let currentDate = Date()
            let calendar = Calendar.current
            let newTimestamp = calendar.date(byAdding: .minute, value: -minutesDiff, to: currentDate)
            
            print("old session timestamp was \(timestamp), new timestamp is \(newTimestamp)")
            
            defaults.set(newTimestamp, forKey: "SessionTimeStamp")
        }
        
        let pluginResult: CDVPluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: true)
        self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
    }
    
    @objc(provideCert:) func provideCert(command: CDVInvokedUrlCommand) {
        let certStr = command.arguments[0] as! String
        let pw = command.arguments[1] as! String
        
        let cert = NSData(base64Encoded: certStr, options: NSData.Base64DecodingOptions(rawValue: UInt(0)))
        
        AuthenticationManager.sharedManager.provideCert(cert! as Data, password: pw)
        
        let pluginResult: CDVPluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: true)
        self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
    }
    
}



