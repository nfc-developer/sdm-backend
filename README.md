# Backend server for decoding Secure Unique NFC Message (SUN)

An example of Flask application which can decrypt data contained in NDEF "mirrors" and validate their AES-CMAC cryptographic signature. Implemented according to _AN12196 "NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints"_.

**Pull requests welcome.**

*Note: NTAG — is a trademark of NXP B.V.*

*Note: This GitHub project is not affiliated with NXP B.V. in any way. Product names are mentioned here in order to inform about compatibility.*

## Contact
Feel free to reach me at ml@icedev.pl if you have any questions concerning this topic.

## Complete solution
If you are looking for a complete solution for tag configuration and management, check out the demo at [kryptonfc.com](https://kryptonfc.com). This app allows you to:

* Personalize blank NFC tags with just an NFC-enabled Android smartphone (no extra hardware required).
* Manage the list of your tags in a web panel.
* View the list of interactions with your tags (each scan is recorded in the table).
* Configure a simple landing page that is displayed to your users after the tag is scanned.
* Access the details about particular interaction through an API, directly from your website.

## How to test?
### Manual installation
1. Clone the repository
   ```
   apt install -y git
   git clone https://github.com/icedevml/sdm-backend.git
   cd sdm-backend
   ```
2. Setup the virtualenv
   ```
   apt install -y python3 python3-pip python3-venv
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install the required dependencies and copy example config:
   ```
   pip3 install -r requirements.txt
   cp config.dist.py config.py
   ```
4. Run Flask development server:
   ```
   python3 app.py --host 0.0.0.0 --port 5000
   ```
5. Visit [localhost:5000](http://127.0.0.1:5000/) and check out the examples.

### Using Docker
1. Run
   ```
   docker run -p 5000:80 icedevml/sdm-backend
   ```
2. Visit [localhost:5000](http://127.0.0.1:5000/) and check out the examples.

## How to setup SDM?
Use NXP's TagWriter application for Android. When writing an URL record, choose "Configure mirroring options". Refer to the tag's datasheet to understand particular options/flags.

## Supported cases
### UID and Read Counter Plaintext mirroring
**Example:**
```
http://myserver.example/tagpt?uid=041E3C8A2D6B80&ctr=000006&cmac=4B00064004B0B3D3
```

**Proposed SDM Settings for TagWriter:**
* [X] Enable SDM Mirroring (SDM Meta Read Access Right: `0E`)
* [X] Enable UID Mirroring
* [X] Enable Counter Mirroring (SDM Counter Retrieval Key: `0F`)
* [ ] Enable Read Counter Limit (Derivation Key for CMAC Calculation: `00`)
* [ ] Encrypted File Data Mirroring

**Input URL:**
```
http://myserver.example/tagpt?uid=00000000000000&ctr=000000&cmac=0000000000000000
```

**UID Offset:**
```
http://myserver.example/tagpt?uid=00000000000000&ctr=000000&cmac=0000000000000000
                                  ^ UID Offset
```

i.e.: in TagWriter, set the cursor between `uid=` and the first `0` when setting offset.

**Counter Offset:**
```
http://myserver.example/tagpt?uid=00000000000000&ctr=000000&cmac=0000000000000000
                                                     ^ Counter Offset
```

**SDMMACInputOffset/SDMMACOffset:**
```
http://myserver.example/tagpt?uid=00000000000000&ctr=000000&cmac=0000000000000000
                                                                 ^ CMAC Offset
```

### PICCData Encrypted mirroring (`CMACInputOffset == CMACOffset`)
**Example:**
```
http://myserver.example/tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086
```
  
**Proposed SDM Settings for TagWriter:**
* [X] Enable SDM Mirroring (SDM Meta Read Access Right: `00`)
* [X] Enable UID Mirroring
* [X] Enable Counter Mirroring (SDM Counter Retrieval Key: `00`)
* [ ] Enable Read Counter Limit
* [ ] Enable Encrypted File Data Mirroring

**Input URL:**
```
http://myserver.example/tag?picc_data=00000000000000000000000000000000&cmac=0000000000000000
```

**PICCDataOffset:**
```
http://myserver.example/tag?picc_data=00000000000000000000000000000000&cmac=0000000000000000
                                      ^ PICCDataOffset
```

i.e.: in TagWriter, set the cursor between `=` and the first `0` when setting offset.

**SDMMACInputOffset/SDMMACOffset:**
```
http://myserver.example/tag?picc_data=00000000000000000000000000000000&cmac=0000000000000000
                                                                            ^ SDMMACInputOffset/SDMMACOffset
```

### SDMENCFileData mirror with PICCData Encrypted mirroring (must satisfy: `CMACInputOffset != CMACOffset && SDMMACInputOffset == ENCDataOffset`)

**Example:**
```
http://myserver.example/tag?picc_data=FD91EC264309878BE6345CBE53BADF40&enc=CEE9A53E3E463EF1F459635736738962&cmac=ECC1E7F6C6C73BF6
```
  
**Proposed SDM Settings for TagWriter:**
* [X] Enable SDM Mirroring (SDM Meta Read Access Right: `00`)
* [X] Enable UID Mirroring
* [X] Enable Counter Mirroring (SDM Counter Retrieval Key: `00`)
* [ ] Enable Read Counter Limit
* [X] Enable Encrypted File Data Mirroring (Encryption data Length: `32`)
* PICC Data Offset: set cursor between `picc_data=` and `0` then click `Set PICC Data Offset`
* Enc Data Offset: set cursor between `enc=` and `0` then click `Set Enc File Mirroring Offset`
* SDM MAC Input Offset: set cursor between `enc=` and `0` then click `Set Offset` (upper button)
* SDM MAC Offset: set cursor between `cmac=` and `0` then click `Set Offset` (lower button)

### TagTamper Status mirror

In this case, TT Status Offset should be equal Enc Data Offset.

**Example:**
```
http://myserver.example/tagtt?picc_data=FDD387BF32A33A7C40CF259675B3A1E2&enc=EA050C282D8E9043E28F7A171464D697&cmac=758110182134ECE9
```

First two letters of `File data (UTF-8)` will describe TagTamper Status (`C` - loop closed, `O` - loop open, `I` - TagTamper not enabled yet).

### Notice about keys
In the examples above, whenever key `00` is mentioned, you can replace it with keys `01` - `04`. It's better not to use master key `00` in production-grade SDM configuration. Whenever possible, it's also better to use different key numbers for different features (e.g. key `01` for SDM Meta Read, key `02` for SDM File Read etc).

Key numbers `0E` and `0F` have a special meaning:

* `0E` - Free access
* `0F` - No access

The interpretation of this meaning is slightly different for each feature, see datasheet for reference.

## Further usage
1. Edit `config.py` to adjust the decryption keys.
2. Setup nginx (with obligatory SSL encryption).
2. Configure the application to run with uwsgi ([example tutorial](https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-uswgi-and-nginx-on-ubuntu-18-04)).

## Using LRP cipher
In general, SDMs generated with LRP cipher are not supported by this code. See [icedevml/nfc-ev2-crypto](https://github.com/icedevml/nfc-ev2-crypto/blob/master/lrp.py) for the implementation of LRP primitive. In [test_lrp_sdm.py](https://github.com/icedevml/nfc-ev2-crypto/blob/master/test_lrp_sdm.py) file, there is a short example of SDM message decryption with LRP primitive.

## Authors

* Michał Leszczyński (ml@icedev.pl)

Feel free to contact if you have any questions.
