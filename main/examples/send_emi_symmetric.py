# In this Example we will see how to send encrypted Messages with Symmetric Key Encryption and a Message Stream

#First connect to a Node
# Required Parameters are node, seed
node = "https://nodes.thetangle.org:443"
seed = "YOUR9SEED9GOES9HERE"
api = emi.connect_to_node(node,seed)

# lets create root address. You got back an unused Address.
root_address = emi.create_root_address()

# We need a Tag too
tag = "IOIOIOIOIISNAJKDHKJ"

#now we need the secret Key to encrypt the message
secret_key = 'TOPSECRET'

# Now to create a Message Stream we will use a for loop.
for i in range(5):
    message = "{}".format(i)
    
    # now we have to create next address
    next_address = emi.create_next_address(root_address)
    print(next_address)
    
    # Create JSON FILE. This is imported because json file must include the message and next_address.
    # Please notic that every json element must be a string.
    json_data = {'message': message,'next_address': str(next_address)}
    json_file = json.dumps(json_data)
    
    #lets encrypt the message
    encrypted_message = emi.encrypt_ske(json_file, secret_key)
    
    
    # lets send the encrypted message
    Finalbundle = emi.send_message(encrypted_message,root_address,tag)
    print(Finalbundle)
    
    #place next_address as root_address to create a loop
    
    root_address = next_address
