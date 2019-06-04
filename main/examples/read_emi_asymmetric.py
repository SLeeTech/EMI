# In this Example we will see how to read encrypted Messages with asymmetric Key Encryption(rsa)

#First connect to a Node
# Required Parameters are node, seed
node = "https://nodes.thetangle.org:443"
seed = "YOUR9SEED9GOES9HERE"
api = emi.connect_to_node(node,seed)

#now we need the root_address
root_address = 'WUGJMZ9DLMWMV9ZBIQCZZS9CUCCCBAMWKXEEEUQMUBXHRGBCSHFSXYABBBTYRMSPFXNFRLD9VSXQWFLSW'
# Now to read the Message Stream we will use a while loop. When we reach the last Message the loop will end.
while True:
    #First we have to finde the Message
    message = emi.find_message(root_address)
    
    json_file = json.loads(message)
    
    #lets print out the message and next_address
    msg = json_file["1"]
    encrypted_key = json_file["2"]
    print("message: " + str(msg))
    print("encrypted key:  " + str(encrypted_key))
    
    decrypted_key = emi.decrypt_pke(encrypted_key,alice_privat_key)
    
    decrypted_message = emi.decrypt_ske(msg,decrypted_key)
    print("decrypted key:  " + str(decrypted_key))
    print("decrypted_message:  " + str(decrypted_message))
    
    json_message = json.loads(decrypted_message)
    next_address = json_message['next_address']
    signature = json_message['signature']
    message = json_message['message']
    verify = emi.verify_signature(bob_public_key, signature,message)
    print("hash algorithmus:  " + str(verify))
    
    # Last step is to place next_addres as root_address
    root_address = next_address
