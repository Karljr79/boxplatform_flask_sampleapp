#Box Platform Demo

####Step1: Install Python, if not done already.
[Go here](http://python.org/download/)

####Step2: Install virtualenv from the command line:
```
$ sudo easy_install virtualenv
```

####Step3: From the root directory of your project, enter the terminal command:
```
$ sudo virtualenv flask
```

####Step 4: Install dependencies in the "requirements.txt" file using the following terminal command:
```
$ sudo flask/bin/pip install -r requirements.txt
```

####Step 5: Update "config.py." The contents of this file should include the following:
To get your Box credentials, [Go Here](https://docs.box.com/docs/getting-started-box-platform)
Leave all of the Auth0 credentials alone. No need to get your own for this demo.
```
#box
CLIENT_ID = 'Your Box Client ID'
CLIENT_SECRET = 'Your Box Client Secret'
EID = 'Your Box Enterprise ID'
KEY_ID = 'Your Public Key ID'
PASSPHRASE = 'Your Private Key Passphrase'
```

####Step 6: Place the private key .pem file you generated from the tutorial below into the project's /app directory:
To generate your private key and configure your app, [Go Here](https://docs.box.com/docs/getting-started-box-platform)


####Step 7: Make sure that the "run.py" script is executable by entering the following terminal command:
```
$ sudo chmod a+x run.py
```

####Step 8: Run the project using the following terminal command and navigate to http://localhost:8080:
```
$ ./run.py
```
