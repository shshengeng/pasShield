let attestationStatus = false;
//let hostname = "";
let usernameinfo = ""


window.addEventListener("message", function(event) {
    //login token
    if (event.data.length == 256) {
        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function (){
            if (xhr.readyState === 4) {
                if (xhr.status === 200) {
                  //successful,xhr.responseText should be a html page
                    console.log(xhr.responseText);
                    let htmlPage = xhr.responseText;
                    // let jsonObject = JSON.parse(xhr.responseText);
                    // let htmlPage = jsonObject["page"];
                    // let cookie = jsonObject["cookie"];
                    // document.cookie = cookie;
                    browser.tabs.query({active: true, currentWindow: true, status: "complete"}, function (tabs) {
                    if(tabs[0] !== undefined){
                        //send string to content.js,then content.js will modify page
                        browser.tabs.sendMessage(tabs[0].id, {content: htmlPage}, function(){
                        });
                    }
                    });
                } else {
                  console.log('Error:', xhr.statusText);
                }
              }
        }
        xhr.open("POST", "https://www.passhield.com/login", true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        console.log(usernameinfo);
        console.log(event.data);
        xhr.send("username=" + usernameinfo + "&token=" + event.data);
    }
    //get register page and sent to content js to modify page
    if(event.data.length != 256 && event.data.length > 30){
        browser.tabs.query({active: true, currentWindow: true, status: "complete"}, function (tabs) {
            if(tabs[0] !== undefined){
                browser.tabs.sendMessage(tabs[0].id, {content: event.data}, function(){
                });
            }
        });
    }
});
  


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
                if(s.substring(0,25) === "Attest successfully"){
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
    if(request.hostname){
        hostname = request.hostname;
    }

    if (request.username && request.password && request.action) {
        //get username,password, action
        const username = request.username;
        usernameinfo = username;
        const password = request.password;
        const action = request.action;
    
        const str = "username="+username+"&"+"password="+password;
        attestOrSent("http://www.passhield.com:81",action,str).then((s) => {
            if(s === "Username and Password sent secretly"){
                console.log("Username and Password sent secretly");
            }else{
                console.log("error");
            }
        });
    } 
});











  
