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
                dictionary_signature = dictionary_items_as_list[2]
                dictionary = self.crypto.symmetric_decrypt(dictionary, decrypted_d_key, 'AES', 'CBC', the_iv)
                dictionary = util.from_json_string(dictionary)
    
            dictionary[uid] = [random_id, random_key_for_value, random_key_for_value_mac]    
            dictionary_iv = self.crypto.get_random_bytes(16)
            string_dict = util.to_json_string(dictionary)
            dictionary_encrypt = self.crypto.symmetric_encrypt(string_dict, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
            
    
            encrypted_value = self.crypto.symmetric_encrypt(value, random_key_for_value, 'AES', 'CBC', value_iv)
            dictionary_encrypt_sign = self.crypto.asymmetric_sign(dictionary_encrypt, self.private_key)
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
        # Replace with your implementation
        try:
            uid = self.resolve(path_join(self.username, name))
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
        # Replace with your implementation (not needed for Part 1)
        uid = path_join(self.username, name)
        username_keys = path_join(self.username, "dict_keys")
        username_dictionary = path_join(self.username, "dictionary")
        random_key_for_dictionary = self.storage_server.get(username_keys)
        random_key_for_dictionary = self.crypto.asymmetric_decrypt(random_key_for_dictionary, self.private_key)
        dictionary_items_as_string = self.storage_server.get(username_dictionary)

        if dictionary_items_as_string is None:
                return None
        dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
        dictionary_iv = dictionary_items_as_list[0]
        encrypted_dictionary = dictionary_items_as_list[1]
        decrypted_dictionary = self.crypto.symmetric_decrypt(encrypted_dictionary, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
        actual_dictionary = util.from_json_string(decrypted_dictionary)

        random_keys = actual_dictionary.get(uid)
        if random_keys is None:
            return None
        random_id = random_keys[0]
        random_id_key = random_keys[1]
        random_id_mac = random_keys[2]


        e_key = self.crypto.asymmetric_encrypt(random_id_key, self.pks.get_public_key(user))

        if self.storage_server.get(random_id+"shared_list") == None:
            shared_list_as_string = util.to_json_string([])
            shared_list_mac = self.crypto.message_authentication_code(shared_list_as_string, random_id_key, 'SHA256')
            shared_list_values = [shared_list_as_string, shared_list_mac]
            shared_list_values_as_string = util.to_json_string(shared_list_values)
            self.storage_server.put(random_id+"shared_list", shared_list_values_as_string)

        shared_list = self.storage_server.get(random_id+"shared_list")
        calculated_mac = self.crypto.message_authentication_code(shared_list, random_id_key, 'SHA256')
        if calculated_mac != shared_list[1]:
            raise IntegrityError() #is this the right error
        shared_list = util.from_json_string(shared_list)
        shared_list[0].append(user)
        self.storage_server.put(random_id+"shared_list", util.to_json_string(shared_list))

        msg_as_list = [random_id, e_key, random_id_mac]
        msg_as_string = util.to_json_string(msg_as_list)

        #they're not gonna test if you call share on something you don't own
        #return None if a user tries to download a file that they don't have access to, not IntegrityError()
        return msg_as_string


        #raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)

        uid = path_join(self.username, name)
        username_keys = path_join(self.username, "dict_keys")
        username_dictionary = path_join(self.username, "dictionary")
        random_key_for_dictionary = self.storage_server.get(username_keys)
        random_key_for_dictionary = self.crypto.asymmetric_decrypt(random_key_for_dictionary, self.private_key)
        dictionary_items_as_string = self.storage_server.get(username_dictionary)

        if dictionary_items_as_string is None:
                return None
        dictionary_items_as_list = util.from_json_string(dictionary_items_as_string)
        dictionary_iv = dictionary_items_as_list[0]
        encrypted_dictionary = dictionary_items_as_list[1]
        decrypted_dictionary = self.crypto.symmetric_decrypt(encrypted_dictionary, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
        actual_dictionary = util.from_json_string(decrypted_dictionary)

        msg = util.from_json_string(message)
        actual_dictionary[newname] = msg

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)

        #does uploading under the same name overwrite the file?
        decrypted_file = download(name)
        upload(self.username, decrypted_file)

        #change alice's list???

        # shared_list = self.storage_server.get(name+"shared_list")
        # #check integrity? mac.
        # for child in shared_list[0]:
        #     change dictionary stuff (delete entry and add new one)
        #     check child's list... change -> 




        