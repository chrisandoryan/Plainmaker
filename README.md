# Plainmaker: Burpsuite Plugin

<h4 align="center">A Simply-implementable and Customizable AESKiller-like Burpsuite Extension<a href="https://github.com/chrisandoryan/Nethive-Project" target="_blank"></a></h4>

## Background
After some hours working to *reverse engineer* the encryption/decryption process of a mobile application, Jojo successfully comes up with a `crypt.py` script that allows him to generate a customized and encrypted HTTP request/response.

However, since <ins>it is a script</ins>, then XX.

Using AESKiller is also not an option because, XX.

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

However:
- There will be no input boxes to insert an AES key and IV; you have to <ins>implement the encryption/decryption algorithm by yourself</ins>.
- But it's just that, *literally*. Simply take your `crypt.py`, make it into a Python class that implements `IEncryptDecrypt` interface, and *voila*. **The encrypted/decrypted values will be injected into Burpsuite's requests/responses automatically.**

## How It Works
 
## Installation
