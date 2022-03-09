# XIVLauncher AutoOTP

This command line tool will help you to automate your login with XIVLauncher and activated OTP through following steps:

 1. Storing your account name together with your OTP secret key protected through Microsofts Data Protection API (or unprotected, but this is not recommended) inside the Windows Credential Manager.
 2. Opening XIVLauncher.exe and waiting for its local OTP web service to start.
 3. Generating your OTP key and sending it to http://localhost:4646/ffxivlauncher/{otp}

## Usage

![Main menu](images/consolemain.png)

If you are using this tool for the first time, you have to start it manually once to set up your OTP secret key.

You have the choice between storing your OTP secret key unprotected (*one click solution but **not safe***) inside the Windows Credential Manager  or protected through Microsofts Data Protection API (**Recommended**) by using an additional password to encrypt it.

Once you are done, you can either login through the manual menu or create a link to this tool and start it with the additional parameter **--Username=** e.g. **--Username=Hildibrand**. Depending on your previous choice of OTP secret key protection, you will be automatically logged in with your account and OTP or asked for your encryption password before generating and passing the OTP to XIVLauncher.
