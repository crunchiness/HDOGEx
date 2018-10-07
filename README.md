Setup
=====
```bash
python3 -m venv venv
. venv/bin/activate
pip install --upgrade setuptools # Might need to run this
pip install wheel                # Might need to run this
pip install -r requirements.txt
```

Notes
=====
```wallet_pb2.py``` file is a [Protobuf](https://developers.google.com/protocol-buffers) file compiled from
```wallet.proto``` which is taken from [bitcoinj](https://github.com/bitcoinj/bitcoinj)
