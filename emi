from iota import Iota
from iota import TryteString, Address
from iota import ProposedTransaction, Tag
from iota.crypto.kerl import Kerl
from iota import Transaction
import json
import rsa
from rsa import PublicKey
import base64
from pyblake2 import blake2b
from cryptography.fernet import Fernet


class emi:

    
    def create_keys(keysize):
        # possible Keysize (bits):
        #128 
        #256 
        #384 
        #512
        #1024
        #2048
        #3072
        #4096
        
        ## generate private an public key
        (pubkey, privkey) = rsa.newkeys(1024)
        return pubkey, privkey
        
    def connect_to_node(node,seed):
        api = Iota(node,seed)
        return api
        
        
    def create_root():
        # create new unused address
        unused_address = api.get_new_addresses(count=None)
        root_address = unused_address['addresses'][0]
        return root_address
    
    def create_next_address(root_address):
        # create next address from root_address
        astrits = TryteString(str(root_address).encode()).as_trits()
        checksum_trits = []
        sponge = Kerl()
        sponge.absorb(astrits)
        sponge.squeeze(checksum_trits)
        result = TryteString.from_trits(checksum_trits) 
        next_address = Address(result)
        
        # check if the next address is unsused
        check_address = api.find_transactions(addresses=[next_address])
        if len(check_address['hashes']) == 0:
            address_empty = True
        else:
            address_empty = False
            
        
        # If new address is used create find an empty address
        if address_empty == False:
            astrits = TryteString((str(next_address)+str(root_address)).encode()).as_trits()
            checksum_trits = []
            sponge = Kerl()
            sponge.absorb(astrits)
            sponge.squeeze(checksum_trits)
            result = TryteString.from_trits(checksum_trits) 
            next_address = Address(result)
        else:
            next_address = next_address
            
        return next_address
    
    def create_secret_key(secret_key):
    ## transfroming the secret_key into Base64 Key
        h = blake2b(digest_size=16)
        h_pw = h.update(bytes(secret_key.encode('utf-8')))
        hh = h.hexdigest()
        pw_string = str(hh).encode('utf-8')
        secret_key = base64.b64encode(pw_string)
        return secret_key
   
        
    
    def create_signature(message, privkey):
        # create signature and transform to hec
        signature = rsa.sign(message.encode('utf-8'), privkey, 'SHA-256')
        hex_signature = signature.hex()
        return hex_signature

    
    def verify_signature(public_key,signature,message):
        # verify signature
        byte_signature = bytes.fromhex(signature)
        verification = rsa.verify(message.encode('ascii'), byte_signature, public_key)
        return verification
    
    def encrypt_message(message):
        ## transfroming the secret_key into Base64 Key
        h = blake2b(digest_size=16)
        h_pw = h.update(bytes(secret_key.encode('utf-8')))
        hh = h.hexdigest()
        pw_string = str(hh).encode('utf-8')
        b64_pw = base64.b64encode(pw_string)
        # encrypt message
        key = b64_pw
        f = Fernet(key)
        token = f.encrypt(bytes(message.encode('utf-8')))
        encrypted_message = token.decode('ascii')
        return encrypted_message

    def decrypt_message(encrypted_message, secret_key):
        h = blake2b(digest_size=16)
        h_pw = h.update(bytes(secret_key.encode('utf-8')))
        hh = h.hexdigest()
        pw_string = str(hh).encode('utf-8')
        b64_pw = base64.b64encode(pw_string)
        ## Decrypt Message
        txn_msg_as_bytes = encrypted_message.encode('ascii')
        key = b64_pw
        f = Fernet(key)
        decrypt_message = f.decrypt(txn_msg_as_bytes)
        return decrypt_message
    


    def send_message(message,root_address,tag):
        
        pt = ProposedTransaction(address = root_address,
                                                message = TryteString.from_unicode(message),
                                                tag     = tag,
                                                value = 0)


        ## Send the Transaction
        FinalBundle = api.send_transfer(depth=3, transfers=[pt], min_weight_magnitude=14)['bundle']

        
        
        return FinalBundle


    def find_message(root_address):
        
        ## find Transaction
        transactions = api.find_transactions(addresses=[root_address])
        txn_hash = transactions['hashes']
        get_txn_bytes = bytes(txn_hash[0])
        get_txn_trytes = api.get_trytes([get_txn_bytes])
        txn_trytes = str(get_txn_trytes['trytes'][0])
        txn = Transaction.from_tryte_string(txn_trytes)
        get_bundle_hash = str(txn.bundle_hash)
        
        #api.find_transactions(bundles=[get_bundle_hash])
        bundle_txn = api.find_transactions(bundles=[get_bundle_hash])['hashes']

        for i in range(0,len(bundle_txn)):
            try:
                bundle = api.get_bundles(bundle_txn[i])
            except:
                pass

        # get all signature_message_fragment from bundle
        length_bundle = len(bundle['bundles'][0])
        txn_tryte_message = ""

        for i in range(0,length_bundle):
            txn_tryte_message += (str(bundle['bundles'][0][i].signature_message_fragment))

        # change format to TryteString(neccessary for decryption)
        padding = TryteString(txn_tryte_message)

        # get the encrypted Message from TryteString
        txn_tryte_string = TryteString.from_unicode(padding)
        encrypted_message = txn_tryte_string.decode()
        
        return encrypted_message


    def extract_json(decrypt_message):
        ## Create json from bytes
        json_string = decrypt_msg.decode("ascii")
        json_file = json.loads(json_string)
        return json_file
