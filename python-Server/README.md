pasShield - Protecting Web Passwords using Intel SGX
=========================================================

Introduction
----------------
This folder is a python server, it uses flask to implement a simple login and register page, it is dynamic, which means your data will be stored at databses.


Installation
---------------
First clone this repo, then run app.py under backend folder in background, you run it by gunicorn(that's we used). You cao do it like this:
```
pip3 install gunicorn\
gunicorn -w 4 -b 127.0.0.1:5001 app.py
```

Make sure install depencies first:
```
pip3 install -r requirements.txt
```




