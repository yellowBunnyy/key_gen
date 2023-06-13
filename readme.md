#### Private key and public key generator with sigined CSR X.509
Discription
Simple app to generate private key and public key generator with sigined CSR X.509.
Working only on linux OS. If want run on win make sure you have instaled 
`open ssl`. 


Technology stack:
- python:
    - re
    - subprocess
    - cryptography
    - tkinter

To use this app firstly (installng all dependencies):
`> poetry install --no-root`,
If you don't have build in tkinter module on python, make:
`> sudo apt-get install python3-tk`
Last step is:
`> python main.py`
That's all.