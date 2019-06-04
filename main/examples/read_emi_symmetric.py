# In this Example we will see how to read a Message Stream and decrypt the Message

#First connect to a Node
# Required Parameters are node, seed
node = "https://nodes.thetangle.org:443"
seed = "YOUR9SEED9GOES9HERE"
api = emi.connect_to_node(node,seed)

#now we need the root_address
root_address = 'ROOT9ADDRESS9GOES9HERE'

#now we need the secret Key to encrypt the message
secret_key = 'TOPSECRET'

# Now to read the Message Stream we will use a while loop. When we reach the last Message the loop will end.
while True:
    #First we have to finde the Message
    message = emi.find_message(root_address)
    
    # Now we have to decrypt the Message
    decrypted_message = emi.decrypt_ske(message,secret_key)
    
    #Extract the json file
    json_file = emi.extract_json(decrypted_message)
    
    #lets print out the message and next_address
    msg = json_file['message']
    next_address = json_file['next_address']
    print(msg)
    print(next_address)
    
    # Last step is to place next_addres as root_address
    root_address = next_address
