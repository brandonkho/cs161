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
        '''
        dictionary = {}

        self.storage_server.put(self.username, (util.to_json_string(self.crypto.get_random_bytes(16)), util.to_json_string(self.crypto.get_random_bytes(16))))

        random_bytes = self.storage_server.get(self.username)[0] #mac key
        random_bytes2 = self.storage_server.get(self.username)[1] #symmetric key

        uid = self.resolve(path_join(self.username, name))
        mac = self.crypto.message_authentication_code(uid, random_bytes, 'SHA')


        mac_value = self.crypto.message_authentication_code(value, random_bytes, 'SHA')


        uid_encrypt = self.crypto.symmetric_encrypt(uid, random_bytes2, 'AES', 'CTR', None, None, self.crypto.new_counter(16), None)
        value_encrypt = self.crypto.symmetric_encrypt(value, random_bytes2, 'AES', 'CTR', None, None, self.crypto.new_counter(16), None)
        #self.storage_server.put(uid, "[DATA] " + value)

        value_encrypt_asym = self.crypto.asymmetric_encrypt(value, self.private_key)
        signature = asymmetric_sign(value_encrypt_asym, self.private_key)

        self.storage_server.put(uid_encrypt, ("[DATA] " + value_encrypt, mac_value))
        

        #raise NotImplementedError
        '''
        uid = self.resolve(path_join(self.username, name))
        random_key_for_name = self.crypto.get_random_bytes(16)
        random_key_for_value = self.crypto.get_random_bytes(16)
        #random_key_value = self.crypto.get_random_bytes(16)
        #iv_name = self.crypto.get_random_bytes(16) 
        #encrypted_name = self.crypto.symmetric_encrypt(uid, random_key_for_name, 'AES', 'CBC', iv_name)
        
        #name_encrypt_sign = self.crypto.asymmetric_sign(uid, self.private_key)


        dict_key = self.crypto.get_random_bytes(16)
        self.storage_server.put("dict_key", self.crypto.asymmetric_encrypt(dict_key,self.private_key))
        dictionary_iv = self.crypto.get_random_bytes(16) #IV for encrypting the dictionary


        
        if self.storage_server.get("dict") is None:
            dictionary = {}

        else:
            dictionary = self.crypto.symmetric_decrypt(util.to_json_string(self.storage_server.get("dict")), dict_key, 'AES', 'CBC', dictionary_iv)
        

        dictionary[uid] = (random_key_for_name, random_key_for_value)
        string_dict = util.to_json_string(dictionary)
        dictionary_encrypt = self.crypto.symmetric_encrypt(string_dict, dict_key, 'AES', 'CBC', dictionary_iv)
        dictionary_encrypt_sign = self.crypto.asymmetric_sign(dictionary_encrypt, self.private_key)

        dict_list = [dictionary_iv, dictionary_encrypt, dictionary_encrypt_sign]
        self.storage_server.put("dict", util.to_json_string(dict_list))
        
        
        
        value_iv = self.crypto.get_random_bytes(16)
        
        encrypted_value = self.crypto.symmetric_encrypt(value, random_key_for_value, 'AES', 'CBC', value_iv)
        #value_encrypt_sign = self.crypto.asymmetric_sign(encrypted_value, self.private_key)



        encrypted_name = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(uid, 'SHA256'), random_key_for_name, 'AES')
        #encrypted_name = self.crypto.symmetric_encrypt(uid, random_key_for_name, 'AES', 'CBC', iv_name)
        #name_encrypt_sign = self.crypto.asymmetric_sign(encrypted_name, self.private_key)


        # signed_name_and_value_list = [value_encrypt_sign, name_encrypt_sign, self.private_key]
        signed_name_and_value = self.crypto.asymmetric_sign(encrypted_name + encrypted_value, self.private_key)

        value_list = [signed_name_and_value, value_iv]
        #name_list = [iv_name, encrypted_name, name_encrypt_sign]
        self.storage_server.put(encrypted_name, util.to_json_string(value_list))




    def download(self, name):
        # Replace with your implementation
        '''
        random_bytes = self.storage_server.get(self.username)[0] #mac key
        random_bytes2 = self.storage_server.get(self.username)[1] #symmetric key

        uid = self.resolve(path_join(self.username, name))


        uid_encrypt = self.crypto.symmetric_encrypt(uid, random_bytes2, 'AES', 'CTR', None, None, self.crypto.new_counter(16), None)


        mac_value = self.crypto.message_authentication_code(value, random_bytes, 'SHA')

        #resp = self.storage_server.get(uid)
        resp = self.storage_server.get(uid_encrypt)

        if resp is None: #rolback
            return None
        if resp[1] != mac_value:
            raise IntegrityError()
        value_decrypt = self.crypto.symmetric_decrypt(resp[0][7:], random_bytes2, 'AES', 'CTR', None, None, self.crypto.new_counter(16), None)
        #return resp[7:]
        return value_decrypt
        
        #raise NotImplementedError
        '''
        uid = self.resolve(path_join(self.username, name))

        dict_key = self.storage_server.get("dict_key")
        decrypted_dict_key = self.crypto.asymmetric_decrypt(dict_key, self.private_key)
        dictionary = self.storage_server.get("dict")
        dict_list = util.from_json_string(dictionary)
        iv = dict_list[0]
        encrypted_dictionary = dict_list[1]
        dictionary_signature = dict_list[2]
        if not self.crypto.asymmetric_verify(encrypted_dictionary, dictionary_signature, self.private_key.publickey()):
            raise IntegrityError()

        decrypted_dictionary = util.from_json_string(self.crypto.symmetric_decrypt(encrypted_dictionary, decrypted_dict_key, 'AES', 'CBC', iv))

        key_that_encrypts_name = decrypted_dictionary[uid][0]
        key_thats_encrypts_value = decrypted_dictionary[uid][1]

        encrypted_name = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(uid, 'SHA256'), key_that_encrypts_name, 'AES')

        resp = self.storage_server.get(encrypted_name)
        if resp is None: #if not in server
            return None
        if resp not in decrypted_dictionary: #if not in dictionary... but should be the same as checking for existence in server
            return None

        decrypted_value_list = util.from_json_string(self.storage_server.get(encrypted_name))

        if not self.crypto.asymmetric_verify(self.storage_server.get(encrypted_name), decrypted_value_list[0], self.private_key.publickey()):
           raise IntegrityError()


        value_decrypt = self.crypto.symmetric_decrypt(decrypted_dictionary[uid], key_thats_encrypts_value, 'AES', 'CBC', decrypted_value_list[1])
        
        return value_decrypt





    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        sharename = path_join(self.username, "sharewith", user, name)
        self.storage_server.put(sharename, "[POINTER] " + path_join(self.username, name))
        return sharename

        #raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        my_id = path_join(self.username, newname)
        self.storage_server.put(my_id, "[POINTER] " + message)

        #raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        sharename = path_join(self.username, "sharewith", user, name)
        self.storage_server.delete(sharename)

        #raise NotImplementedError
