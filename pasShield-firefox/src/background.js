// src/background.js
const { AttestationClient } = require("@azure/attestation");





function comingHeaders(details){
    if( details.responseHeaders === undefined ) {
        console.warn( "pasShield: no headers in the response" );
        //console.log(details);
        return;
    }

    details.responseHeaders.foreach(function());

}



//
firefox.webRequest.onHeadersReceived.addListener(
    comingHeaders,
    {urls: ["<all_urls>"]},
    ["responseHeaders", "blocking"]
);

