var sgx_enabled = false;


document.addEventListener("DOMContentLoaded", function() {

    // var tmp = 0;
    // var metas = document.getElementsByTagName('meta');
    // console.log("passhiled: before checking for SGX Enabled meta tag");
    // for (var i=0; i<metas.length; i++) { 
    //     if (metas[i].getAttribute("name") == "SGXEnabled") { 
    //         tmp = tmp + 1;
    //     }
    // }

    // if(tmp !== 0){ 
    //     sgx_enabled = true; 
    //     browser.runtime.sendMessage({type: "SGXEnabled"});
    // }else{
    //     sgx_enabled = false; 
    //     browser.runtime.sendMessage({type: "SGXNotEnabled"});
    // }

    
    browser.runtime.onMessage.addListener( function(request, sender, sendResponse) {
        if (request.check === "SGXEnabled?") {
            if(sgx_enabled == false) {
                sendResponse({answer: "SGXNotEnabled"});
            }else {
                sendResponse({answer: "SGXEnabled"});
            }
        }else if(request.SGXEnabled === "true"){
            sgx_enabled = true;
            sendResponse({answer: "SGXEnabled"});
        }else if(request.SGXNotEnabled === "true"){
            sgx_enabled = false;
            sendResponse({answer: "SGXNotEnabled"});
        }
    });
});