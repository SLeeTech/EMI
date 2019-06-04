# In this Example we will see how to send encrypted Messages with asymmetric Key Encryption(rsa)
#First connect to a Node
# Required Parameters are node, seed
node = "https://papa.iota.family:14267"
seed = "YOUR9SEED9GOES9HERE"
api = emi.connect_to_node(node,seed)

# lets create root address. You got back an unused Address.
root_address = emi.create_root_address()
print("root:  " + str(root_address))
# We need a Tag too
tag = "IOIOINSDIOIISNAJKDHKJ"

# Define the Keys. For this example we will use the emi.create_keys function to create Keys. Keysize = 1024
# Alice is the reciever and Bob the sender
# Bob will signing the message with his public key
alice_public_key, alice_privat_key = emi.create_keys(1024)
bob_public_key, bob_privat_key = emi.create_keys(1024)

#now we need the secret Key to encrypt the message
secret_key = 'TOPSECRET'

# A secret key for symmetric encryption is required because the message file is to big to encrypt with rsa.
# We will encrypt the message file with symmetric key encryption and the secret key with public key encryption.


# Creating Message Stream. In this Example we will use a for loop.
for i in range(5):
    
    message = "{}".format(i)
    
    # now we have to create next address
    next_address = emi.create_next_address(root_address)
    print("next:  " + str(next_address))
    
    # create Bob Signature
    signature = emi.create_signature(message,bob_privat_key)
    print("signature: " + signature)
    
    
    #Create json file
    message_data = {'message': message, 'next_address': str(next_address), 'signature': signature}
    message_json = json.dumps(message_data)
    
    #lets encrypt the message
    encrypted_message = emi.encrypt_ske(message_json, secret_key)
    
    #encrypt the secret key with public key from alice
    encrypted_secret_key = emi.encrypt_pke(secret_key, alice_public_key) 
    
    # Lets create a json file. 1 will be encrypted_message and 2 will be encryptet_secret_key
    json_data = {'1': encrypted_message, '2': encrypted_secret_key}
    json_file = json.dumps(json_data)
    
    # send message
    Finalbundle = emi.send_message(json_file,root_address,tag)
    print(Finalbundle)
    

    #place next_address as root_address to create a loop
    root_address = next_address
