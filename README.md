# Plainmaker: Burpsuite Plugin

<h4 align="center">A Programmable and Implementable AESKiller-like Burpsuite Extension<a href="https://github.com/chrisandoryan/Nethive-Project" target="_blank"></a></h4>

## Background
After some hours working to *reverse engineer* the encryption/decryption process of a mobile application, Jojo successfully comes up with a `crypt.py` script that allows him to generate a customized and encrypted HTTP requests and responses.

However, since <ins>it is a script</ins>, then Jojo must copy the values outputted by the script, paste it into Burpsuite, then send it away.

[TBA GIF Example]

Using <a href="https://github.com/Ebryx/AES-Killer" target="_blank">AESKiller</a> is also not an option because, for example: 
- The *mobile application* uses a customized AES encryption flow, with different key and IV for encrypting and decrypting HTTP requests and responses.
- Some operations (e.g., XOR) must be done to the key or IV  before it can be used in the encryption/decryption process.
- The key or IV is dynamically generated, or must be retrieved from somewhere in the HTTP request/response.
- Or perhaps, the *mobile application* simply does not use AES for its encryption/decryption process.

So, if sometimes in the future you find yourself suffering like Jojo, this repository might be for you.

## Features

 - A fully-customizable and implementable Interface class, named `IEncryptorDecryptor`, for creating your own Burpsuite Plugin/Extension.
 - This interface allows you to implement your custom encryption/decryption algorithms and integrate them directly into Burpsuite requests and responses.
 - You have total control on **how the encryption/decryption flow works**, and **which algorithms to be used**. AES? RSA? DES? Lattice-based Cryptography? You name it.
 - Based on Python/Jython 2.7.3.

## What It Does
In hindsight, this is similar to what AESKiller is doing:
- The IProxyListener decrypt requests and encrypt responses, and an IHttpListener than encrypt requests and decrypt responses.
- Burp sees the decrypted traffic, including Repeater, Intruder and Scanner, but the client/mobile app and server see the encrypted version.

However, there will be no static input boxes to insert an AES key and IV; you have the freedom to <ins>implement the flow of the encryption/decryption by yourself</ins>.

### Huh? Then?
Simply take your encryption/decryption script (like Jojo's `crypt.py`), then adjust it into a Python class that implements `IEncryptDecrypt` interface, and *voila*. **The encrypted/decrypted values will be injected into Burpsuite's requests/responses automatically.**

## How It Works
 
## Installation
