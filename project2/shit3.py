"""Secure client implementation
This is a skeleton file for you to build your secure file store client.
Fill in the methods for the class Client per the project specification.
You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
import util

def path_join(*strings):
    """Joins a list of strings putting a "/" between each.
    :param strings: a list of strings to join
    :returns: a string
    """
    return '/'.join(strings)


class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        

    def resolve(self, uid):
        while True:
            res = self.storage_server.get(uid)
            if res is None or res.startswith("[DATA]"):
                return uid
            elif res.startswith("[POINTER]"):
                uid = res[10:]
            else:
                raise IntegrityError()


    def upload(self, name, value):
        # Replace with your implementation
        

        
        try:
            dictionary  = None
            d_key = None
            uid = self.resolve(path_join(self.username, name))
            #random_key_for_name = self.crypto.get_random_bytes(16)
            random_id = self.crypto.get_random_bytes(16)
            random_key_for_value = self.crypto.get_random_bytes(16)
            random_key_for_dictionary = self.crypto.get_random_bytes(16)
            random_key_for_value_mac = self.crypto.get_random_bytes(16)
            random_key_for_dict_mac = self.crypto.get_random_bytes(16)
    
            value_iv = self.crypto.get_random_bytes(16)

            encrypted_random_key_for_dictionary = self.crypto.asymmetric_encrypt(random_key_for_dictionary, self.private_key.publickey())
            username_keys = path_join(self.username, "dict_keys")
            username_dictionary = path_join(self.username, "dictionary")

            #print(encrypted_random_key_for_dictionary)

            if self.storage_server.get(username_keys) is None:
                self.storage_server.put(username_keys, encrypted_random_key_for_dictionary)
            else:
                e_random_key_for_dictionary = self.storage_server.get(username_keys)
                random_key_for_dictionary = self.crypto.asymmetric_decrypt(e_random_key_for_dictionary, self.private_key)
            if self.storage_server.get(username_dictionary) is None:
                dictionary = {}
    
            else:
                
                d_key = self.storage_server.get(username_keys)
                decrypted_d_key = self.crypto.asymmetric_decrypt(d_key, self.private_key)
                dictionary_items_as_string = self.storage_server.get(username_dictionary)
                dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
                the_iv = dictionary_items_as_list[0]
                dictionary = dictionary_items_as_list[1]
                dictionary_signature = dictionary_items_as_list[2]
                #if not self.crypto.asymmetric_verify(dictionary, dictionary_signature, self.private_key.publickey()):
                    #raise IntegrityError()
                dictionary = self.crypto.symmetric_decrypt(dictionary, decrypted_d_key, 'AES', 'CBC', the_iv)
                dictionary = util.from_json_string(dictionary)
    
    
    
    
            dictionary[uid] = [random_id, random_key_for_value, random_key_for_value_mac]
    
    
            dictionary_iv = self.crypto.get_random_bytes(16)
            string_dict = util.to_json_string(dictionary)
            dictionary_encrypt = self.crypto.symmetric_encrypt(string_dict, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
            
    
            encrypted_value = self.crypto.symmetric_encrypt(value, random_key_for_value, 'AES', 'CBC', value_iv)
            ##########################
            dictionary_encrypt_sign = self.crypto.asymmetric_sign(dictionary_encrypt, self.private_key)
            dictionary_encrypt_mac = self.crypto.message_authentication_code(dictionary_encrypt, random_key_for_dict_mac, 'SHA256')

            #name_encrypt_sign = self.crypto.asymmetric_sign(encrypted_name, self.private_key)
            #value_encrypt_sign = self.crypto.asymmetric_sign(encrypted_value, self.private_key)
            #signed_name_and_value = self.crypto.asymmetric_sign(random_id+encrypted_value, self.private_key)
            ##########################
            name_and_value_encrypt_mac = self.crypto.message_authentication_code(random_id+encrypted_value, random_key_for_value_mac, 'SHA256')

    
            list_of_value_items = [value_iv, encrypted_value, name_and_value_encrypt_mac]
            list_of_value_items_as_string = util.to_json_string(list_of_value_items)
    
            #self.storage_server.put("dict", string_dict)
            list_of_items = [dictionary_iv, dictionary_encrypt, dictionary_encrypt_mac]
            list_of_items_as_string = util.to_json_string(list_of_items)
            self.storage_server.put(username_dictionary, list_of_items_as_string)
            #self.storage_server.put("dict", dictionary_encrypt)
            #self.storage_server.put(encrypted_name, "[DATA] " + value)
            self.storage_server.put(random_id, "[DATA] " + list_of_value_items_as_string)
        except:
            raise IntegrityError()

    def download(self, name):
        # Replace with your implementation
        

        
        try:
            uid = self.resolve(path_join(self.username, name))
            username_keys = path_join(self.username, "dict_keys")
            #print(username_keys)
            if username_keys is None:
                return None
            username_dictionary = path_join(self.username, "dictionary")
            random_key_for_dictionary = self.storage_server.get(username_keys)
            #print(random_key_for_dictionary)
            if random_key_for_dictionary is None:
                return None
            random_key_for_dictionary = self.crypto.asymmetric_decrypt(random_key_for_dictionary, self.private_key)
            dictionary_items_as_string = self.storage_server.get(username_dictionary)

            #print(dictionary_items_as_string)
            if dictionary_items_as_string is None:
                return None
            dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
            dictionary_iv = dictionary_items_as_list[0]
            encrypted_dictionary = dictionary_items_as_list[1]
            ###############
            encrypted_dictionary_mac = dictionary_items_as_list[2]
            #if not self.crypto.asymmetric_verify(encrypted_dictionary, encrypted_dictionary_signature, self.private_key.publickey()):
                #raise IntegrityError()
                #pass
            ###############
            #encrypted_dictionary = dictionary_items_as_string
            #decrypted_dictionary = self.crypto.asymmetric_decrypt(encrypted_dictionary, self.private_key)
            decrypted_dictionary = self.crypto.symmetric_decrypt(encrypted_dictionary, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
            actual_dictionary = util.from_json_string(decrypted_dictionary)
            #actual_dictionary = dictionary_items_as_list
            random_keys = actual_dictionary.get(path_join(self.username, name))
            #print(random_keys)
            if random_keys is None:
                return None
            random_id = random_keys[0]
            random_key_for_value = random_keys[1]
            random_key_for_value_mac = random_keys[2]
            #resp = self.storage_server.get(uid)
            #encrypted_name = self.crypto.symmetric_encrypt(uid, random_key_for_name, 'AES')
            resp = self.storage_server.get(random_id)
            if resp is None:
                return None
            list_of_value_items_as_string = resp[7:]
            list_of_value_items = util.from_json_string(list_of_value_items_as_string)
            value_iv = list_of_value_items[0]
            encrypted_value = list_of_value_items[1]
            #encrypted_value_signature = list_of_value_items[2]
            ###########
            name_and_value_encrypt_mac = list_of_value_items[2]
            '''
            if not self.crypto.asymmetric_verify(random_id+encrypted_value, signed_name_and_value, self.private_key.publickey()):
                raise IntegrityError()
            ###########

            if not self.crypto.asymmetric_verify(encrypted_value, encrypted_value_signature, self.private_key.publickey()):
                raise IntegrityError()
                #pass
            '''
            calculated_mac = self.crypto.message_authentication_code(random_id+encrypted_value, random_key_for_value_mac, 'SHA256')
            if calculated_mac != name_and_value_encrypt_mac:
                raise IntegrityError()
            decrypted_value = self.crypto.symmetric_decrypt(encrypted_value, random_key_for_value, 'AES', 'CBC', value_iv)
            return decrypted_value
        except:
            raise IntegrityError()
    


    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        uid = path_join(self.username, name)
        username_keys = path_join(self.username, "dict_keys")
        username_dictionary = path_join(self.username, "dictionary")
        random_key_for_dictionary = self.storage_server.get(username_keys)
        #print(random_key_for_dictionary)
        random_key_for_dictionary = self.crypto.asymmetric_decrypt(random_key_for_dictionary, self.private_key)
        dictionary_items_as_string = self.storage_server.get(username_dictionary)

        #print(dictionary_items_as_string)
        if dictionary_items_as_string is None:
                return None
        dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
        dictionary_iv = dictionary_items_as_list[0]
        encrypted_dictionary = dictionary_items_as_list[1]
        decrypted_dictionary = self.crypto.symmetric_decrypt(encrypted_dictionary, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
        actual_dictionary = util.from_json_string(decrypted_dictionary)

        random_keys = actual_dictionary.get(uid)
        #print(random_keys)
        if random_keys is None:
            return None
        random_id = random_keys[0]
        random_key_for_value = random_keys[1]
        random_key_for_value_mac = random_keys[2]
        

        sharename = path_join(self.username, "sharewith", user, name)
        self.storage_server.put(sharename, "[POINTER] " + random_id)
        return sharename

        #raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        '''
        random_key_for_value = self.crypto.get_random_bytes(16)
        random_key_for_dictionary = self.crypto.get_random_bytes(16)
        random_key_for_value_mac = self.crypto.get_random_bytes(16)
        random_key_for_dict_mac = self.crypto.get_random_bytes(16)


        uid = path_join(from_username, newname)
        from_username_keys = path_join(from_username, "dict_keys")
        from_username_dictionary = path_join(from_username, "dictionary")
        from_user_random_key = self.storage_server.get(username_keys)
        #print(random_key_for_dictionary)
        from_user_random_key = self.crypto.asymmetric_decrypt(from_user_random_key, self.private_key)
        dictionary_items_as_string = self.storage_server.get(username_dictionary)

        #print(dictionary_items_as_string)
        if dictionary_items_as_string is None:
                return None
        dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
        dictionary_iv = dictionary_items_as_list[0]
        encrypted_dictionary = dictionary_items_as_list[1]
        decrypted_dictionary = self.crypto.symmetric_decrypt(encrypted_dictionary, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
        actual_dictionary = util.from_json_string(decrypted_dictionary)

        random_keys = actual_dictionary.get(uid)
        #print(random_keys)
        if random_keys is None:
            return None
        random_id = random_keys[0]

        value_iv = self.crypto.get_random_bytes(16)
        encrypted_random_key_for_dictionary = self.crypto.asymmetric_encrypt(random_key_for_dictionary, self.private_key.publickey())
        username_keys = path_join(self.username, "dict_keys")
        username_dictionary = path_join(self.username, "dictionary")
        #print(encrypted_random_key_for_dictionary)
        if self.storage_server.get(username_keys) is None:
            self.storage_server.put(username_keys, encrypted_random_key_for_dictionary)
        else:
            e_random_key_for_dictionary = self.storage_server.get(username_keys)
            random_key_for_dictionary = self.crypto.asymmetric_decrypt(e_random_key_for_dictionary, self.private_key)

        if self.storage_server.get(username_dictionary) is None:
                dictionary = {}
    
        else:
            
            d_key = self.storage_server.get(username_keys)
            decrypted_d_key = self.crypto.asymmetric_decrypt(d_key, self.private_key)
            dictionary_items_as_string = self.storage_server.get(username_dictionary)
            dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
            the_iv = dictionary_items_as_list[0]
            dictionary = dictionary_items_as_list[1]
            dictionary_signature = dictionary_items_as_list[2]
            #if not self.crypto.asymmetric_verify(dictionary, dictionary_signature, self.private_key.publickey()):
                #raise IntegrityError()
            dictionary = self.crypto.symmetric_decrypt(dictionary, decrypted_d_key, 'AES', 'CBC', the_iv)
            dictionary = util.from_json_string(dictionary)

        dictionary[uid] = [random_id, random_key_for_value, random_key_for_value_mac]
    
    
        dictionary_iv = self.crypto.get_random_bytes(16)
        string_dict = util.to_json_string(dictionary)
        dictionary_encrypt = self.crypto.symmetric_encrypt(string_dict, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
        
        
        dictionary_encrypt_mac = self.crypto.message_authentication_code(dictionary_encrypt, random_key_for_dict_mac, 'SHA256')
        
        

        #self.storage_server.put("dict", string_dict)
        list_of_items = [dictionary_iv, dictionary_encrypt, dictionary_encrypt_mac]
        list_of_items_as_string = util.to_json_string(list_of_items)
        self.storage_server.put(username_dictionary, list_of_items_as_string)
        '''
        my_id = path_join(self.username, newname)
        self.storage_server.put(my_id, "[POINTER] " + message)




        random_key_for_value = self.crypto.get_random_bytes(16)
        random_key_for_value_mac = self.crypto.get_random_bytes(16)
        uid = self.resolve(path_join(self.username, newname))
        username_keys = path_join(self.username, "dict_keys")
        username_dictionary = path_join(self.username, "dictionary")
        random_key_for_dictionary = self.crypto.get_random_bytes(16)
        encrypted_random_key_for_dictionary = self.crypto.asymmetric_encrypt(random_key_for_dictionary, self.private_key.publickey())

        if self.storage_server.get(username_keys) is None:
            self.storage_server.put(username_keys, encrypted_random_key_for_dictionary)
        else:
            e_random_key_for_dictionary = self.storage_server.get(username_keys)
            random_key_for_dictionary = self.crypto.asymmetric_decrypt(e_random_key_for_dictionary, self.private_key)
        if self.storage_server.get(username_dictionary) is None:
            dictionary = {}

        else:
            
            d_key = self.storage_server.get(username_keys)
            decrypted_d_key = self.crypto.asymmetric_decrypt(d_key, self.private_key)
            dictionary_items_as_string = self.storage_server.get(username_dictionary)
            dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
            the_iv = dictionary_items_as_list[0]
            dictionary = dictionary_items_as_list[1]
            dictionary_signature = dictionary_items_as_list[2]
            #if not self.crypto.asymmetric_verify(dictionary, dictionary_signature, self.private_key.publickey()):
                #raise IntegrityError()
            dictionary = self.crypto.symmetric_decrypt(dictionary, decrypted_d_key, 'AES', 'CBC', the_iv)
            dictionary = util.from_json_string(dictionary)

        dictionary[my_id] = [uid, random_key_for_value, random_key_for_value_mac]
    
    
        dictionary_iv = self.crypto.get_random_bytes(16)
        string_dict = util.to_json_string(dictionary)
        dictionary_encrypt = self.crypto.symmetric_encrypt(string_dict, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
        
        
        dictionary_encrypt_mac = self.crypto.message_authentication_code(dictionary_encrypt, random_key_for_dict_mac, 'SHA256')
        
        

        #self.storage_server.put("dict", string_dict)
        list_of_items = [dictionary_iv, dictionary_encrypt, dictionary_encrypt_mac]
        list_of_items_as_string = util.to_json_string(list_of_items)
        self.storage_server.put(username_dictionary, list_of_items_as_string)

        #raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        sharename = path_join(self.username, "sharewith", user, name)
        self.storage_server.delete(sharename)

        #raise NotImplementedError