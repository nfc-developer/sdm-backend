# Backend server for NTAG 424 DNA Secure Direct Messaging (SDM)

An example of Flask application which can decrypt and validate signature of Secure Direct Messaging "mirrors". Implemented according to _AN12196 "NTAG 424 DNA and NTAG 424 DNA TagTamper features and
hints"_.

*Note: NTAG — is a trademark of NXP B.V.*

## Supported cases
* PICCData Encrypted mirroring (`CMACInputOffset == CMACOffset`)

  *Example:*
  ```
  http://myserver.example/tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086
  ```
* SDMENCFileData mirror with PICCData Encrypted mirroring (must satisfy: `CMACInputOffset != CMACOffset && SDMMACInputOffset == ENCDataOffset`)

  *Example:*
  ```
  http://myserver.example/tag?picc_data=FD91EC264309878BE6345CBE53BADF40&enc=CEE9A53E3E463EF1F459635736738962&cmac=ECC1E7F6C6C73BF6
  ```

## How to test?
1. Clone the repository
   ```
   git clone https://github.com/icedevml/ntag424-dna-server.git
   cd ntag424-dna-server
   ```
2. Install the required dependencies and copy example config:
   ```
   pip3 install -r requirements.txt
   cp config.dist.py config.py
   ```
3. Run Flask development server:
   ```
   python3 app.py --host 127.0.0.1 --port 5000
   ```
4. Visit [localhost:5000](http://127.0.0.1:5000/) and check out the examples.

## Further usage
1. Edit `config.py` to adjust the decryption keys.
2. Setup nginx (with obligatory SSL encryption).
2. Configure the application to run with uwsgi ([example tutorial](https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-uswgi-and-nginx-on-ubuntu-18-04)).
