var sgx_enabled = false;


document.addEventListener("DOMContentLoaded", function() {

    var tmp = 0;
    var metas = document.getElementsByTagName('meta');
    console.log("passhiled: before checking for SGX Enabled meta tag");
    for (var i=0; i<metas.length; i++) { 
        if (metas[i].getAttribute("name") == "SGXEnabled") { 
            tmp = tmp + 1;
        }
    }

    if(tmp !== 0){ 
        sgx_enabled = true;
        browser.runtime.sendMessage({type: "SGXEnabled"});
    }else{
        sgx_enabled = false; 
        browser.runtime.sendMessage({type: "SGXNotEnabled"});
    }

    
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
        }else if(request.content){
            var root = document.documentElement;
            root.innerHTML = request.content;
        }
    });


    if(sgx_enabled == true){
        let inputObjs = document.getElementsByTagName("input");
        for (let i = 0; i < inputObjs.length; i++) {
            const e = inputObjs[i];
            if((e.type == "text" && e.name == "username")){
                e.style.border = "2px solid green";
                e.style.borderBottom = "1.5px solid green";

                const div = document.createElement('div');
                div.setAttribute('id', 'div1');
                div.textContent = 'Data will be sent in a secure chanle'; 
                div.style.cssText = 'margin-left: 10px; display: none; width: 50px; height: 50px; background-color: #99FF99; color: black;'; 
                e.insertAdjacentElement('afterend', div);

                let divObj = document.getElementById("div1");

                e.addEventListener("mouseenter", function(){
                    divObj.style.display = "inline";
                });

                e.addEventListener("mouseleave", function(){
                    divObj.style.display = "none";
                });
            }
            if((e.type == "password")){
                e.style.border = "2px solid green";
                e.style.borderTop = "1.5px solid green"

                const div = document.createElement('div');
                div.setAttribute('id', 'div2');
                div.textContent = 'Data will be sent in a secure chanle'; 
                div.style.cssText = 'margin-left: 10px; display: none; width: 50px; height: 50px; background-color: #99FF99; color: black;'; 
                e.insertAdjacentElement('afterend', div);

                let divObj = document.getElementById("div2");

                e.addEventListener("mouseenter", function(){
                    divObj.style.display = "inline";
                });

                e.addEventListener("mouseleave", function(){
                    divObj.style.display = "none";
                });
            }
        }
    }

    if(sgx_enabled == true){
        //get form dom object
        const form = document.querySelector('form');
        form.addEventListener('submit', (event) => {
            event.preventDefault(); // prevent default action

            //get username and passoword user typed in 
            const tmpValue = form.getAttribute('action');
            const actionValue = tmpValue.substring(1);
            const username = form.querySelector('input[name="username"]').value;
            const password = form.querySelector('input[name="password"]').value;

            //send app, username and password to background js
            browser.runtime.sendMessage({action: actionValue, username: username, password: password});

            //form.submit();
        });
    }
});