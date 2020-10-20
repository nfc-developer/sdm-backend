# Backend server for NTAG 424 DNA Secure Direct Messaging (SDM)

An example of Flask application which can decrypt and validate signature of Secure Direct Messaging "mirrors". Implemented according to _AN12196 "NTAG 424 DNA and NTAG 424 DNA TagTamper features and
hints"_.

**Pull requests welcome.**

*Note: NTAG — is a trademark of NXP B.V.*

## How to test?
### Manual installation
1. Clone the repository
   ```
   apt install -y git
   git clone https://github.com/icedevml/ntag424-backend.git
   cd ntag424-backend
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
   docker run -p 5000:80 icedevml/ntag424-backend
   ```
2. Visit [localhost:5000](http://127.0.0.1:5000/) and check out the examples.

## How to setup SDM?
Use NXP's TagWriter application for Android. When writing an URL record, choose "Configure mirroring options". Refer to the tag's datasheet to understand particular options/flags.

## Supported cases
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

i.e.: in TagWriter, set the cursor between `=` and `0` when setting offset.

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
* [X] Enable Encrypted File Data Mirroring (Encryption data Length: `16`)

## Further usage
1. Edit `config.py` to adjust the decryption keys.
2. Setup nginx (with obligatory SSL encryption).
2. Configure the application to run with uwsgi ([example tutorial](https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-uswgi-and-nginx-on-ubuntu-18-04)).

## Dealing with LRP cipher
In general, SDMs generated with LRP cipher are not supported by this code. See [icedevml/ntag424-ev2-crypto](https://github.com/icedevml/ntag424-ev2-crypto/blob/master/lrp.py) for the implementation of LRP primitive. In [test_lrp_sdm.py](https://github.com/icedevml/ntag424-ev2-crypto/blob/master/test_lrp_sdm.py) file, there is a short example of SDM message decryption with LRP primitives.

## Contact
Feel free to reach me at ml@icedev.pl if you have any questions concerning this topic.
