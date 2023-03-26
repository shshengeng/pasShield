let attestationStatus = false;


//set icon and popup
function setIconAndPopup(iconPath, popupPath, callback) {
    browser.browserAction.setIcon(iconPath, callback);
    browser.browserAction.setPopup(popupPath, callback);
}


function attestOrSent(url, app, message){
    const go = new Go();

    return new Promise((resolve, reject) => {
        (async function() {
            const result = await WebAssembly.instantiateStreaming(fetch("../wasm/main.wasm"), go.importObject);
            go.run(result.instance);

            const s = attest(url, app, message);   
            resolve(s);
        })();
    });
}


//receiving response 
function oncomingHeaders(details){
    if( details.responseHeaders === undefined ) {
        console.warn( "pasShield: no headers in the response" );
        //console.log(details);
        return;
    }
    //check response headers
    details.responseHeaders.forEach(function(v,i,a){
        if( v.name == "Ego-Enclave-Attestation" ) {
            console.log( "pasShield: verifying with Ego Client" );
            //attestation done
            attestOrSent("http://www.passhield.com:81","secret","attestation").then((s) => {
                console.log(s)
                if(s === "Attest successfully"){
                    attestationStatus = true;
                    browser.tabs.query({active: true, currentWindow: true, status: "complete"}, function (tabs) {
                        if(tabs[0] !== undefined){
                            browser.tabs.sendMessage(tabs[0].id, {SGXEnabled:"true"}, function(response){
                                if( response === undefined || response.answer === undefined ) {
                                    return
                                }
                                if(response.answer === "SGXEnabled") {
                                    setIconAndPopup({path: 'imgs/icons/shield.png'}, {popup: 'html/supported.html'}, function() {
                                        console.log("Icon and popup set successfully.");
                                    });
                                }
                            });
                        }
                    });
                }else {
                    attestationStatus = false
                    browser.tabs.query({active: true, currentWindow: true, status: "complete"}, function (tabs) {
                        if(tabs[0] !== undefined){
                            browser.tabs.sendMessage(tabs[0].id, {SGXNotEnabled:"true"}, function(response) {
                                if( response === undefined || response.answer === undefined ) {
                                    return
                                }
                                if(response.answer === "SGXNotEnabled") { 
                                    setIconAndPopup({path: 'imgs/icons/cross.png'}, {popup: 'html/unsupported.html'}, function() {
                                        console.log("Icon and popup set failed.");
                                    });
                                }
                            });
                        }
                    });
                }
            });
        }
    });
}


browser.webRequest.onHeadersReceived.addListener(
    oncomingHeaders,
    {urls: ["<all_urls>"]},
    ["responseHeaders", "blocking"]
);


//inject content script when we switch from one active tab to another
browser.tabs.onActivated.addListener(function(info) {
    browser.tabs.query({active: true, currentWindow: true, status: "complete"}, function (tabs) {
        if(tabs[0] !== undefined){
            browser.tabs.sendMessage(tabs[0].id, {check: "SGXEnabled?"}, function (response) {
                if( response === undefined || response.answer === undefined ) {
                    return
                }
                if(response.answer === "SGXEnabled") {
                    setIconAndPopup({path: 'imgs/icons/shield.png'}, {popup: 'html/supported.html'}, function() {
                        console.log("Icon and popup set successfully.");
                    });
                }
                else if(response.answer === "SGXNotEnabled") { 
                    setIconAndPopup({path: 'imgs/icons/cross.png'}, {popup: 'html/unsupported.html'}, function() {
                        console.log("Icon and popup set failed.");
                    });
                }
            });
        }
    });
});


browser.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    //one side communication, the content script just sends a message about sgx in the beginning
    if(request.type === "SGXEnabled"){
        setIconAndPopup({path: 'imgs/icons/shield.png'}, {popup: 'html/supported.html'}, function() {
            console.log("Icon and popup set successfully.");
        });
    } else if (request.type === "SGXNotEnabled"){
        setIconAndPopup({path: 'imgs/icons/cross.png'}, {popup: 'html/unsupported.html'}, function() {
            console.log("Icon and popup set failed.");
        });
    }

    if (request.username && request.password && request.action) {
        //get username,password, action
        const username = request.username;
        const password = request.password;
        const action = request.action
    
        const str = "username="+username+"&"+"password="+password;
        attestOrSent("http://www.passhield.com:81","secret",str).then((s) => {
            if(s === "Username and Password sent secretly"){
                console.log("Username and Password sent secretly")
            }else{
                console.log("error")
            }
        });
    } 
});






  
