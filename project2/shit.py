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
            random_key_for_name = self.crypto.get_random_bytes(16)
            random_key_for_value = self.crypto.get_random_bytes(16)
            random_key_for_dictionary = self.crypto.get_random_bytes(16)

            ###########
            random_id = self.crypto.get_random_bytes(16)
            ###########
    
            value_iv = self.crypto.get_random_bytes(16)
    
            if self.storage_server.get("dict_key") is None:
                self.storage_server.put("dict_key", random_key_for_dictionary)
            else:
                random_key_for_dictionary = self.storage_server.get("dict_key")
            if self.storage_server.get("dict") is None:
                dictionary = {}
    
            else:
                #dictionary = util.from_json_string(self.storage_server.get("dict"))
                #dictionary = self.crypto.asymmetric_decrypt(dictionary, self.private_key)
                '''
                dictionary = self.storage_server.get("dict")
                dictionary = self.crypto.asymmetric_decrypt(dictionary, self.private_key)
                dictionary = util.from_json_string(dictionary)
                '''
                d_key = self.storage_server.get("dict_key")
                dictionary_items_as_string = self.storage_server.get("dict")
                dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
                the_iv = dictionary_items_as_list[0]
                dictionary = dictionary_items_as_list[1]
                dictionary_signature = dictionary_items_as_list[2]
                #if not self.crypto.asymmetric_verify(dictionary, dictionary_signature, self.private_key.publickey()):
                    #raise IntegrityError()
                dictionary = self.crypto.symmetric_decrypt(dictionary, d_key, 'AES', 'CBC', the_iv)
                dictionary = util.from_json_string(dictionary)
    
    
    
    
            #dictionary[uid] = (random_key_for_name, random_key_for_value)
            dictionary[path_join(self.username, name)] = (random_id, random_key_for_value)
    
            dictionary_iv = self.crypto.get_random_bytes(16)
            string_dict = util.to_json_string(dictionary)
            #dictionary_encrypt = self.crypto.asymmetric_encrypt(string_dict, self.private_key.publickey())
            dictionary_encrypt = self.crypto.symmetric_encrypt(string_dict, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
    
            #dictionary_items_as_list = [dictionary_iv, dictionary_encrypt]
            #dictionary_items_as_string = util.to_json_string(dictionary_items_as_list)
    
            #encrypted_name = self.crypto.symmetric_encrypt(uid, random_key_for_name, 'AES')

    
            encrypted_value = self.crypto.symmetric_encrypt(value, random_key_for_value, 'AES', 'CBC', value_iv)
            ##########################
            dictionary_encrypt_sign = self.crypto.asymmetric_sign(dictionary_encrypt, self.private_key)
            #name_encrypt_sign = self.crypto.asymmetric_sign(encrypted_name, self.private_key)
            value_encrypt_sign = self.crypto.asymmetric_sign(encrypted_value, self.private_key)
            signed_name_and_value = self.crypto.asymmetric_sign(random_id+encrypted_value, self.private_key)
            ##########################
    
            list_of_value_items = [value_iv, encrypted_value, value_encrypt_sign, signed_name_and_value]
            list_of_value_items_as_string = util.to_json_string(list_of_value_items)
    
            #self.storage_server.put("dict", string_dict)
            list_of_items = [dictionary_iv, dictionary_encrypt, dictionary_encrypt_sign]
            list_of_items_as_string = util.to_json_string(list_of_items)
            self.storage_server.put("dict", list_of_items_as_string)
            #self.storage_server.put("dict", dictionary_encrypt)
            #self.storage_server.put(encrypted_name, "[DATA] " + value)
            #self.storage_server.put(encrypted_name, "[DATA] " + list_of_value_items_as_string)
            self.storage_server.put(random_id, "[DATA] " + list_of_value_items_as_string)
        except:
            raise IntegrityError()

    def download(self, name):
        # Replace with your implementation
        

        
        
        uid = self.resolve(path_join(self.username, name))
        random_key_for_dictionary = self.storage_server.get("dict_key")
        dictionary_items_as_string = self.storage_server.get("dict")
        
        if dictionary_items_as_string is None:
            return None
        dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
        dictionary_iv = dictionary_items_as_list[0]
        encrypted_dictionary = dictionary_items_as_list[1]
        ###############
        encrypted_dictionary_signature = dictionary_items_as_list[2]
        #if not self.crypto.asymmetric_verify(encrypted_dictionary, encrypted_dictionary_signature, self.private_key.publickey()):
            #raise IntegrityError()
            #pass
        ###############
        #encrypted_dictionary = dictionary_items_as_string
        #decrypted_dictionary = self.crypto.asymmetric_decrypt(encrypted_dictionary, self.private_key)
        decrypted_dictionary = self.crypto.symmetric_decrypt(encrypted_dictionary, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
        actual_dictionary = util.from_json_string(decrypted_dictionary)
        #actual_dictionary = dictionary_items_as_list
        #print(uid)
        random_keys = actual_dictionary.get(uid)
        if random_keys is None:
            return None
        #random_key_for_name = random_keys[0]
        random_id = random_keys[0]
        random_key_for_value = random_keys[1]
        #resp = self.storage_server.get(uid)
        #encrypted_name = self.crypto.symmetric_encrypt(uid, random_key_for_name, 'AES')
        #resp = self.storage_server.get(encrypted_name)
        resp = self.storage_server.get(random_id)
        if resp is None:
            return None
        list_of_value_items_as_string = resp[7:]
        list_of_value_items = util.from_json_string(list_of_value_items_as_string)
        value_iv = list_of_value_items[0]
        
        encrypted_value = list_of_value_items[1]
        '''
        encrypted_value_signature = list_of_value_items[2]
        ###########
        signed_name_and_value = list_of_value_items[3]
        if not self.crypto.asymmetric_verify(random_id+encrypted_value, signed_name_and_value, self.private_key.publickey()):
            raise IntegrityError()
        ###########
        if not self.crypto.asymmetric_verify(encrypted_value, encrypted_value_signature, self.private_key.publickey()):
            raise IntegrityError()
            #pass
        '''
        decrypted_value = self.crypto.symmetric_decrypt(encrypted_value, random_key_for_value, 'AES', 'CBC', value_iv)
        return decrypted_value
        
    


    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        sharename = path_join(self.username, "sharewith", user, name)
        uid = path_join(self.username, name)
        random_key_for_dictionary = self.storage_server.get("dict_key")
        dictionary_items_as_string = self.storage_server.get("dict")
           
        if dictionary_items_as_string is None:
            return None
        dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
        dictionary_iv = dictionary_items_as_list[0]
        encrypted_dictionary = dictionary_items_as_list[1]
        encrypted_dictionary_signature = dictionary_items_as_list[2]
        decrypted_dictionary = self.crypto.symmetric_decrypt(encrypted_dictionary, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
        actual_dictionary = util.from_json_string(decrypted_dictionary)
        random_keys = actual_dictionary.get(uid)
        #if random_keys is None:
            #return None
        random_id = random_keys[0]
        random_key_for_value = random_keys[1]
        '''
        #share_uid = path_join(user, name)
        actual_dictionary[uid] = (random_id, random_key_for_value)
    
        dictionary_iv = self.crypto.get_random_bytes(16)
        string_dict = util.to_json_string(actual_dictionary)
        dictionary_encrypt = self.crypto.symmetric_encrypt(string_dict, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)

        
        dictionary_encrypt_sign = self.crypto.asymmetric_sign(dictionary_encrypt, self.private_key)
        
        list_of_items = [dictionary_iv, dictionary_encrypt, dictionary_encrypt_sign]
        list_of_items_as_string = util.to_json_string(list_of_items)
        self.storage_server.put("dict", list_of_items_as_string)
        '''

        self.storage_server.put(sharename, "[POINTER] " + random_id)
        return sharename

        #raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        '''
        d_key = self.storage_server.get("dict_key")
        dictionary_items_as_string = self.storage_server.get("dict")
        dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
        the_iv = dictionary_items_as_list[0]
        dictionary = dictionary_items_as_list[1]
        dictionary_signature = dictionary_items_as_list[2]
        dictionary = self.crypto.symmetric_decrypt(dictionary, d_key, 'AES', 'CBC', the_iv)
        dictionary = util.from_json_string(dictionary)
        random_id = self.crypto.get_random_bytes(16)
        random_key_for_value = self.crypto.get_random_bytes(16)
        dictionary[uid] = (random_id, random_key_for_value)
        '''
        d_key = self.storage_server.get("dict_key")
        dictionary_items_as_string = self.storage_server.get("dict")
        dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
        the_iv = dictionary_items_as_list[0]
        dictionary = dictionary_items_as_list[1]
        dictionary_signature = dictionary_items_as_list[2]
        dictionary = self.crypto.symmetric_decrypt(dictionary, d_key, 'AES', 'CBC', the_iv)
        dictionary = util.from_json_string(dictionary)

        from_users_random_id = dictionary.get(path_join(from_username, newname))

        my_id = path_join(self.username, newname)

        dictionary[my_id] = from_users_random_id

        dictionary_iv = self.crypto.get_random_bytes(16)
        string_dict = util.to_json_string(dictionary)

        dictionary_encrypt = self.crypto.symmetric_encrypt(string_dict, d_key, 'AES', 'CBC', dictionary_iv)

        list_of_items = [dictionary_iv, dictionary_encrypt, 'LOL']
        list_of_items_as_string = util.to_json_string(list_of_items)
        self.storage_server.put("dict", list_of_items_as_string)

        self.storage_server.put(my_id, "[POINTER] " + message)

        #raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        sharename = path_join(self.username, "sharewith", user, name)
        self.storage_server.delete(sharename)

        #raise NotImplementedError