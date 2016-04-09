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
        try:
            dictionary  = None
            d_key = None
            uid = self.resolve(path_join(self.username, name))

            random_id = self.crypto.get_random_bytes(16)
            random_key_for_value = self.crypto.get_random_bytes(16)
            random_key_for_dictionary = self.crypto.get_random_bytes(16)
            random_key_for_value_mac = self.crypto.get_random_bytes(16)
            random_key_for_dict_mac = self.crypto.get_random_bytes(16)
    
            value_iv = self.crypto.get_random_bytes(16)

            encrypted_random_key_for_dictionary = self.crypto.asymmetric_encrypt(random_key_for_dictionary, self.private_key.publickey())
            username_keys = path_join(self.username, "dict_keys")
            username_dictionary = path_join(self.username, "dictionary")

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
                dictionary = self.crypto.symmetric_decrypt(dictionary, decrypted_d_key, 'AES', 'CBC', the_iv)
                dictionary = util.from_json_string(dictionary)
                if dictionary.get(path_join(self.username, name)) is not None:
                    random_id = dictionary.get(path_join(self.username, name))[0]
                    random_key_for_value = dictionary.get(path_join(self.username, name))[1]
                    random_key_for_value_mac = dictionary.get(path_join(self.username, name))[2]  

            if uid.startswith("[SHARE]"):
                shared_info = self.get_shared_random_shit(uid)
                shared_info = util.from_json_string(shared_info)
                random_id = shared_info[1]
                random_key_for_value = shared_info[2]
                random_key_for_value_mac = shared_info[3]

            dictionary[path_join(self.username, name)] = [random_id, random_key_for_value, random_key_for_value_mac]   
            dictionary_iv = self.crypto.get_random_bytes(16)
            dictionary_as_string = util.to_json_string(dictionary)
            dictionary_encrypt = self.crypto.symmetric_encrypt(dictionary_as_string, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
            encrypted_value = self.crypto.symmetric_encrypt(value, random_key_for_value, 'AES', 'CBC', value_iv)
            dictionary_encrypt_mac = self.crypto.message_authentication_code(dictionary_encrypt, random_key_for_dict_mac, 'SHA256')
            name_and_value_encrypt_mac = self.crypto.message_authentication_code(random_id+encrypted_value, random_key_for_value_mac, 'SHA256')

            list_of_value_items = [value_iv, encrypted_value, name_and_value_encrypt_mac]
            list_of_value_items_as_string = util.to_json_string(list_of_value_items)
            list_of_items = [dictionary_iv, dictionary_encrypt, dictionary_encrypt_mac]
            list_of_items_as_string = util.to_json_string(list_of_items)
            self.storage_server.put(username_dictionary, list_of_items_as_string)
            self.storage_server.put(random_id, "[DATA] " + list_of_value_items_as_string)
        except:
            raise IntegrityError()

    def download(self, name):        
        try:
            uid = self.resolve(path_join(self.username, name))

            if uid.startswith("[SHARE]"):
                if self.storage_server.get(uid) is None:
                    pass
                else:
                    return self.get_shared_info(uid)

            username_keys = path_join(self.username, "dict_keys")
            if username_keys is None:
                return None

            username_dictionary = path_join(self.username, "dictionary")
            random_key_for_dictionary = self.storage_server.get(username_keys)

            if random_key_for_dictionary is None:
                return None
            random_key_for_dictionary = self.crypto.asymmetric_decrypt(random_key_for_dictionary, self.private_key)
            dictionary_items_as_string = self.storage_server.get(username_dictionary)


            if dictionary_items_as_string is None:
                return None
            dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
            dictionary_iv = dictionary_items_as_list[0]
            encrypted_dictionary = dictionary_items_as_list[1]
            encrypted_dictionary_mac = dictionary_items_as_list[2]
            decrypted_dictionary = self.crypto.symmetric_decrypt(encrypted_dictionary, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
            actual_dictionary = util.from_json_string(decrypted_dictionary)
            random_keys = actual_dictionary.get(path_join(self.username, name))

            if random_keys is None:
                return None
            random_id = random_keys[0]
            random_key_for_value = random_keys[1]
            random_key_for_value_mac = random_keys[2]

            resp = self.storage_server.get(random_id)
            if resp is None:
                return None

            list_of_value_items_as_string = resp[7:]
            list_of_value_items = util.from_json_string(list_of_value_items_as_string)
            value_iv = list_of_value_items[0]
            encrypted_value = list_of_value_items[1]
            name_and_value_encrypt_mac = list_of_value_items[2]
            
            calculated_mac = self.crypto.message_authentication_code(random_id+encrypted_value, random_key_for_value_mac, 'SHA256')
            if calculated_mac != name_and_value_encrypt_mac:
                raise IntegrityError()
            
            decrypted_value = self.crypto.symmetric_decrypt(encrypted_value, random_key_for_value, 'AES', 'CBC', value_iv)
            return decrypted_value
        
        except:
            raise IntegrityError() 


    def share(self, user, name):
        uid = self.resolve(path_join(self.username, name))

        sharename = path_join("[SHARE]", self.username, "sharewith", user, name)

        if uid.startswith("[SHARE]"):
            shared_info = self.get_shared_random_shit(uid)
            #encrypt the shared_info
            self.storage_server.put(sharename, "[POINTER] " + path_join(self.username, name))
            return sharename #msg = [sharename]


        dictionary = self.retrieve_dict()

        random_keys = dictionary.get(path_join(self.username, name))
 
        if random_keys is None: #when you try to share something you don't have access to; get rid of this?
            return None

        random_id = random_keys[0]
        random_key_for_value = random_keys[1]
        random_key_for_value_mac = random_keys[2]     
        message = [sharename, random_id, random_key_for_value, random_key_for_value_mac]
        message_as_string = util.to_json_string(message)
        self.storage_server.put(sharename, "[DATA] " + message_as_string)
        return sharename


    def receive_share(self, from_username, newname, message):        
        my_id = path_join(self.username, newname)
        self.storage_server.put(my_id, "[POINTER] " + message) #message[i] if we add more stuff to message

    def revoke(self, user, name):
        sharename = path_join("[SHARE]", self.username, "sharewith", user, name)
        self.storage_server.delete(sharename)

        #go through alice's list and change value of pointers

        #raise NotImplementedError


    def retrieve_dict(self):
        username_dictionary = path_join(self.username, "dictionary")
        username_keys = path_join(self.username, "dict_keys")
        if self.storage_server.get(username_dictionary) is None:
            dictionary = {}
            return dictionary
            
        d_key = self.storage_server.get(username_keys)
        decrypted_d_key = self.crypto.asymmetric_decrypt(d_key, self.private_key)
        dictionary_items_as_string = self.storage_server.get(username_dictionary)
        dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
        the_iv = dictionary_items_as_list[0]
        dictionary = dictionary_items_as_list[1]
        dictionary = self.crypto.symmetric_decrypt(dictionary, decrypted_d_key, 'AES', 'CBC', the_iv)
        dictionary = util.from_json_string(dictionary)
        return dictionary

    def get_shared_info(self, uid): #add stuff to decrypt the [DATA] [random_id, random_key] #get decrypted value of random_id
        shared_info = self.storage_server.get(uid)[7:]
        info_as_list = util.from_json_string(shared_info)
        random_id = info_as_list[1]
        random_key_for_value = info_as_list[2]
        random_key_for_value_mac = info_as_list[3]
        resp = self.storage_server.get(random_id)
        if resp is None:
            return None
        list_of_value_items_as_string = resp[7:]
        list_of_value_items = util.from_json_string(list_of_value_items_as_string)
        value_iv = list_of_value_items[0]
        encrypted_value = list_of_value_items[1]
        name_and_value_encrypt_mac = list_of_value_items[2]
        calculated_mac = self.crypto.message_authentication_code(random_id+encrypted_value, random_key_for_value_mac, 'SHA256')
        if calculated_mac != name_and_value_encrypt_mac:
            raise IntegrityError()
        decrypted_value = self.crypto.symmetric_decrypt(encrypted_value, random_key_for_value, 'AES', 'CBC', value_iv)
        return decrypted_value


    def get_shared_random_shit(self, uid): #get [random_id, random_key]
        shared_info = self.storage_server.get(uid)[7:]
        return shared_info