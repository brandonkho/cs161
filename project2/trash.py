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

            data_key = self.crypto.get_random_bytes(16)
            data_mac_key = self.crypto.get_random_bytes(16)
    
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
                    data_key = dictionary.get(path_join(self.username, name))[3]
                    data_mac_key = dictionary.get(path_join(self.username, name))[4]

            if uid.startswith("[SHARE]"):
                items_for_data_and_value = dictionary.get(path_join(self.username ,name))
                data_key = items_for_data_and_value[3]
                data_mac_key = items_for_data_and_value[4]
                list_of_data_items_as_string = self.storage_server.get(uid)[7:]
                list_of_data_items = util.from_json_string(list_of_data_items_as_string)
                data_iv = list_of_data_items[0]
                encrypted_data_as_string = list_of_data_items[1]
                data_mac = list_of_data_items[2]
                calculated_data_mac = self.crypto.message_authentication_code(encrypted_data_as_string, data_mac_key, 'SHA256')
                if calculated_data_mac != data_mac:
                    raise IntegrityError()
                data = self.crypto.symmetric_decrypt(encrypted_data_as_string, data_key, 'AES', 'CBC', data_iv)
                shared_info = util.from_json_string(data)
                random_id = shared_info[0]
                random_key_for_value = shared_info[1]
                random_key_for_value_mac = shared_info[2]
                dictionary[path_join(self.username, name)] = [random_id, random_key_for_value, random_key_for_value_mac, data_key, data_mac_key]
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
                return
            
            
            dictionary[path_join(self.username, name)] = [random_id, random_key_for_value, random_key_for_value_mac, data_key, data_mac_key]
    

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

            uid = path_join(self.username, name)
            d = self.retrieve_dict()
            random_id = d.get(path_join(self.username, name))[0]
            uid = self.resolve(random_id)

            if uid.startswith("[SHARE]"):
                if self.storage_server.get(uid) is None:
                    return None
                else:
                    dictionary = self.retrieve_dict()
                    items_for_data_and_value = dictionary.get(path_join(self.username, name))
                    
                    data_key = items_for_data_and_value[3]
                    
                    data_mac_key = items_for_data_and_value[4]
                    return self.get_shared_info(uid, data_key, data_mac_key)

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
        share_file = None
        if self.storage_server.get(path_join(self.username, "share_file", name)) is None:
            share_file = []
        else:
            share_file_as_string = self.storage_server.get(path_join(self.username, "share_file", name))
            share_file = util.from_json_string(share_file_as_string)

        share_file.append(user)
        share_file_as_string = util.to_json_string(share_file)
        self.storage_server.put(path_join(self.username, "share_file", name), share_file_as_string)

        random_id = self.crypto.get_random_bytes(16)


        uid = self.resolve(path_join(self.username, name))

        sharename = path_join("[SHARE]", self.username, "sharewith", user, random_id)

        if uid.startswith("[SHARE]"):
            shared_info = self.storage_server.get(uid)[7:]
            #encrypt the shared_info
            dictionary = self.retrieve_dict()
            random_keys = dictionary.get(path_join(self.username, name))
            random_id = random_keys[0]
            sharename = path_join("[SHARE]", self.username, "sharewith", user, random_id)
            data_key = random_keys[3]
            data_mac_key = random_keys[4]

            self.storage_server.put(sharename, "[POINTER] " + path_join(self.username, random_id))
            sharing_message = [sharename, data_key, data_mac_key]
            sharing_message_as_string = util.to_json_string(sharing_message)
            #return sharename #msg = [sharename]
            return sharing_message_as_string

        dictionary = self.retrieve_dict()

        random_keys = dictionary.get(path_join(self.username, name))
 
        if random_keys is None: #when you try to share something you don't have access to; get rid of this?
            return None

        random_id = random_keys[0]
        sharename = path_join("[SHARE]", self.username, "sharewith", user, random_id)
        random_key_for_value = random_keys[1]
        random_key_for_value_mac = random_keys[2]     
        data = [random_id, random_key_for_value, random_key_for_value_mac]
        data_as_string = util.to_json_string(data)

        #####
        data_key = random_keys[3]
        data_iv = self.crypto.get_random_bytes(16)
        data_mac_key = random_keys[4]
        ########
        username_keys = path_join(self.username, "dict_keys")
        username_dictionary = path_join(self.username, "dictionary")
        random_key_for_dictionary = self.storage_server.get(username_keys)
        random_key_for_dictionary = self.crypto.asymmetric_decrypt(random_key_for_dictionary, self.private_key)

        dictionary[path_join(self.username, name)] = [random_id, random_key_for_value, random_key_for_value_mac, data_key, data_mac_key]

        dictionary_iv = self.crypto.get_random_bytes(16)
        dictionary_as_string = util.to_json_string(dictionary)
        dictionary_encrypt = self.crypto.symmetric_encrypt(dictionary_as_string, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
        #dictionary_encrypt_mac = self.crypto.message_authentication_code(dictionary_encrypt, random_key_for_dict_mac, 'SHA256')
        list_of_items = [dictionary_iv, dictionary_encrypt, None]
        list_of_items_as_string = util.to_json_string(list_of_items)
        self.storage_server.put(username_dictionary, list_of_items_as_string)
        ########
        encrypted_data_as_string = self.crypto.symmetric_encrypt(data_as_string, data_key, 'AES', 'CBC', data_iv)
        data_mac = self.crypto.message_authentication_code(encrypted_data_as_string, data_mac_key, 'SHA256')
        list_of_data_items = [data_iv, encrypted_data_as_string, data_mac]
        list_of_data_items_as_string = util.to_json_string(list_of_data_items)
        self.storage_server.put(sharename, "[DATA] " + list_of_data_items_as_string)

        message = [sharename, data_key, data_mac_key]
        message_as_string = util.to_json_string(message)
        return message_as_string


    def receive_share(self, from_username, newname, message):
        #print(message)
        message_as_list = util.from_json_string(message)
        sharename = message_as_list[0]
        data_key = message_as_list[1]
        data_mac_key = message_as_list[2]

        dictionary  = None
        uid = self.resolve(path_join(self.username, newname))
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
        dictionary = self.retrieve_dict()

        dictionary[path_join(self.username, newname)] = [random_id, random_key_for_value, random_key_for_value_mac, data_key, data_mac_key]

        dictionary_iv = self.crypto.get_random_bytes(16)
        dictionary_as_string = util.to_json_string(dictionary)
        dictionary_encrypt = self.crypto.symmetric_encrypt(dictionary_as_string, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
        dictionary_encrypt_mac = self.crypto.message_authentication_code(dictionary_encrypt, random_key_for_dict_mac, 'SHA256')
        list_of_items = [dictionary_iv, dictionary_encrypt, dictionary_encrypt_mac]
        list_of_items_as_string = util.to_json_string(list_of_items)
        self.storage_server.put(username_dictionary, list_of_items_as_string)

        #my_id = path_join(self.username, newname)
        my_id = random_id

        self.storage_server.put(my_id, "[POINTER] " + sharename) #message[i] if we add more stuff to message

    def revoke(self, user, name):
        sharename = path_join("[SHARE]", self.username, "sharewith", user, name)
        self.storage_server.delete(sharename)

        username_dictionary = path_join(self.username, "dictionary")

        dictionary = self.retrieve_dict()
        random_key_for_dictionary = self.storage_server.get(path_join(self.username, "dict_keys"))
        random_key_for_dictionary = self.crypto.asymmetric_decrypt(random_key_for_dictionary, self.private_key)
        random_key_for_dict_mac = self.crypto.get_random_bytes(16)
        value_iv = self.crypto.get_random_bytes(16)

        random_keys = dictionary.get(path_join(self.username, name))
 
        if random_keys is None: #when you try to share something you don't have access to; get rid of this?
            return None

        random_id = random_keys[0]
        random_key_for_value = random_keys[1]
        random_key_for_value_mac = random_keys[2]
        ####
        data_key = random_keys[3]
        data_mac_key = random_keys[4]
        ####
        decrypted_value = self.get_value(random_keys)

        new_random_id = self.crypto.get_random_bytes(16)
        new_random_key_for_value = self.crypto.get_random_bytes(16)
        new_random_key_for_value_mac = self.crypto.get_random_bytes(16)

        dictionary[path_join(self.username, name)] = [new_random_id, new_random_key_for_value, new_random_key_for_value_mac, data_key, data_mac_key]

        dictionary_iv = self.crypto.get_random_bytes(16)
        dictionary_as_string = util.to_json_string(dictionary)
        dictionary_encrypt = self.crypto.symmetric_encrypt(dictionary_as_string, random_key_for_dictionary, 'AES', 'CBC', dictionary_iv)
        encrypted_value = self.crypto.symmetric_encrypt(decrypted_value, new_random_key_for_value, 'AES', 'CBC', value_iv)
        dictionary_encrypt_mac = self.crypto.message_authentication_code(dictionary_encrypt, random_key_for_dict_mac, 'SHA256')
        name_and_value_encrypt_mac = self.crypto.message_authentication_code(new_random_id+encrypted_value, new_random_key_for_value_mac, 'SHA256')
        list_of_value_items = [value_iv, encrypted_value, name_and_value_encrypt_mac]
        list_of_value_items_as_string = util.to_json_string(list_of_value_items)
        list_of_items = [dictionary_iv, dictionary_encrypt, dictionary_encrypt_mac]
        list_of_items_as_string = util.to_json_string(list_of_items)
        self.storage_server.put(username_dictionary, list_of_items_as_string)
        self.storage_server.put(new_random_id, "[DATA] " + list_of_value_items_as_string)


        

        share_file_as_string = self.storage_server.get(path_join(self.username, "share_file", name))
        share_file = util.from_json_string(share_file_as_string)


        #data = [sharename, new_random_id, new_random_key_for_value, new_random_key_for_value_mac]
        data = [new_random_id, new_random_key_for_value, new_random_key_for_value_mac]
        data_as_string = util.to_json_string(data)
        data_iv = self.crypto.get_random_bytes(16)
        
        encrypted_data_as_string = self.crypto.symmetric_encrypt(data_as_string, data_key, 'AES', 'CBC', data_iv)
        data_mac = self.crypto.message_authentication_code(encrypted_data_as_string, data_mac_key, 'SHA256')
        
        list_of_data_items = [data_iv, encrypted_data_as_string, data_mac]
        list_of_data_items_as_string = util.to_json_string(list_of_data_items)
        for child in share_file:
            if child != user:
                
                self.storage_server.put(path_join("[SHARE]", self.username, "sharewith", child, name), "[DATA] " + list_of_data_items_as_string)

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

    def get_shared_info(self, uid, data_key, data_mac_key): #add stuff to decrypt the [DATA] [random_id, random_key] #get decrypted value of random_id
        list_of_data_items_as_string = self.storage_server.get(uid)[7:]
        list_of_data_items = util.from_json_string(list_of_data_items_as_string)
        
        data_iv = list_of_data_items[0]
        
        encrypted_data_as_string = list_of_data_items[1]
        
        data_mac = list_of_data_items[2]
        calculated_data_mac = self.crypto.message_authentication_code(encrypted_data_as_string, data_mac_key, 'SHA256')
        if calculated_data_mac != data_mac:
            raise IntegrityError()
        shared_info = self.crypto.symmetric_decrypt(encrypted_data_as_string, data_key, 'AES', 'CBC', data_iv)
        info_as_list = util.from_json_string(shared_info)
        random_id = info_as_list[0]
        random_key_for_value = info_as_list[1]
        random_key_for_value_mac = info_as_list[2]
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



    def get_value(self, random_keys):
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


    

