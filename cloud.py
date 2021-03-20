from basic_defs import cloud_storage, NAS
from credentials import aws_credentials, gcp_credentials, azure_credentials

import boto3
from azure.storage.blob import BlobServiceClient
from google.cloud import storage

import os
import sys
import re
import hashlib

class AWS_S3(cloud_storage):
    def __init__(self):
        # TODO: Fill in the AWS access key ID
        #self.access_key_id = aws_credentials.access_key_id
        # TODO: Fill in the AWS access secret key
        #self.access_secret_key = aws_credentials.access_secret_key
        # TODO: Fill in the bucket name
        self.bucket_name = aws_credentials.bucket_name
        self.s3 = boto3.resource(service_name = 's3', aws_access_key_id = aws_credentials.access_key_id, aws_secret_access_key = aws_credentials.access_secret_key)
        self.aws_bucket = self.s3.Bucket(aws_credentials.bucket_name)
                    
        

    # Implement the abstract functions from cloud_storage
    # Hints: Use the following APIs from boto3
    #     boto3.session.Session:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html
    #     boto3.resources:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/guide/resources.html
    #     boto3.s3.Bucket:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#bucket
    #     boto3.s3.Object:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#object
    def list_blocks(self):
        # Return list of all objects present under the bucket
        obj_list = []
        for obj in self.aws_bucket.objects.all():
            obj_list.append(int(obj.key))
        return obj_list

    def read_block(self, offset):
        try:
            return bytearray(self.s3.Object(self.bucket_name, str(offset)).get()['Body'].read())
        except:
            return ''

    def write_block(self, block, offset):
        self.s3.Object(self.bucket_name, str(offset)).put(Body=block)

    def delete_block(self, offset):
        try:
            self.s3.Object(self.bucket_name, str(offset)).delete()
            return 1
        except:
            return 0

class Azure_Blob_Storage(cloud_storage):
    def __init__(self):
        # TODO: Fill in the Azure key
        #self.key = azure_credentials.key
        # TODO: Fill in the Azure connection string
        #self.conn_str = azure_credentials.conn_str
        # TODO: Fill in the account name
        #self.account_name = "csce678s21"
        # TODO: Fill in the container name
        self.container_name = azure_credentials.container_name
        self.azure_service_client = BlobServiceClient.from_connection_string(azure_credentials.conn_str)
        self.azure_bucket = self.azure_service_client.get_container_client(azure_credentials.container_name)

    # Implement the abstract functions from cloud_storage
    # Hints: Use the following APIs from azure.storage.blob
    #    blob.BlobServiceClient:
    #        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blobserviceclient?view=azure-python
    #    blob.ContainerClient:
    #        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.containerclient?view=azure-python
    #    blob.BlobClient:
    #        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blobclient?view=azure-python
    def list_blocks(self):
        # Return list of all objects present under the bucket
        obj_list = []
        for obj in self.azure_bucket.list_blobs():
            obj_list.append(int(obj.name))
        return obj_list

    def read_block(self, offset):
        try:
            return bytearray(self.azure_service_client.get_blob_client(container=self.container_name, blob=str(offset)).download_blob().readall())
        except:
            return ''
    def write_block(self, block, offset):
        self.azure_service_client.get_blob_client(container=self.container_name, blob=str(offset)).upload_blob(block, overwrite= True)

    def delete_block(self, offset):
        try:
            self.azure_service_client.get_blob_client(container=self.container_name, blob=str(offset)).delete_blob()
            return 1
        except:
            return 0

class Google_Cloud_Storage(cloud_storage):
    def __init__(self):
        # Google Cloud Storage is authenticated with a **Service Account**
        # TODO: Download and place the Credential JSON file
        #self.credential_file = "gcp-credential.json"
        # TODO: Fill in the container name
        #self.bucket_name = gcp_credentials.bucket_name
        self.gcp_storage_client = storage.Client.from_service_account_json("gcp-credential.json")
        self.gcp_bucket = self.gcp_storage_client.bucket(gcp_credentials.bucket_name)

    # Implement the abstract functions from cloud_storage
    # Hints: Use the following APIs from google.cloud.storage
    #    storage.client.Client:
    #        https://googleapis.dev/python/storage/latest/client.html
    #    storage.bucket.Bucket:
    #        https://googleapis.dev/python/storage/latest/buckets.html
    #    storage.blob.Blob:
    #        https://googleapis.dev/python/storage/latest/blobs.html
    def list_blocks(self):
        # Return list of all objects present under the bucket
        obj_list = []
        for obj in self.gcp_storage_client.list_blobs(self.gcp_bucket):
            obj_list.append(int(obj.name))
        return obj_list

    def read_block(self, offset):
        try:
            return bytearray(self.gcp_bucket.blob(str(offset)).download_as_string())
        except:
            return ''
    def write_block(self, block, offset):
        self.gcp_bucket.blob(str(offset)).upload_from_string(str(block))

    def delete_block(self, offset):
        try:
            self.gcp_bucket.blob(str(offset)).delete()
            return 1
        except:
            return 0

class RAID_on_Cloud(NAS):
    def __init__(self):
        self.backends = [
                AWS_S3(),
                Azure_Blob_Storage(),
                Google_Cloud_Storage()
            ]
        self.fds = dict()
        self.block_size_limit = cloud_storage.block_size
        
    # Generic functions to make the code more readable
    def cloud_storage_mapping(self, filename_tmp):
        return hash(filename_tmp) % 3

    # Implement the abstract functions from NAS
    def open(self, filename):
        # Return an unused numeric value for reference
        newfd = None
        for fd in range(256):
            if fd not in self.fds:
                newfd = fd
                break
        if newfd is None:
            raise IOError("Opened files exceed system limitation.")
        self.fds[newfd] = filename
        #print(filename)
        return newfd

    def read(self, fd, length, offset):
        if fd not in self.fds:
            #raise IOError("File descriptor %d does not exist." % fd)
            return ''
            
        # Initialising variables to read
        file_offset = offset % self.block_size_limit
        alignment_offset = offset / self.block_size_limit
        backend_offset = self.fds[fd] + '_'
        data_block = ''
        data_to_read = length + file_offset
        
        
        
        # Start reading  from first block till last
        while data_to_read > 0:
            backend_offset_tmp = backend_offset + str(alignment_offset*self.block_size_limit)
            cloud_mapping = self.cloud_storage_mapping(backend_offset_tmp)
            if cloud_mapping == 0:

                data_block_temp = self.backends[0].read_block(str(hash(backend_offset_tmp)))
                #if data_block_temp == '':
                #    print("$$$$$$$$$$$$$$$$" + str(cloud_mapping))

            elif cloud_mapping == 1:

                data_block_temp = self.backends[1].read_block(str(hash(backend_offset_tmp)))
                #if data_block_temp == '':
                #    print("$$$$$$$$$$$$$$$$" + str(cloud_mapping))

            else:

                data_block_temp = self.backends[2].read_block(str(hash(backend_offset_tmp)))
                #if data_block_temp == '':
                #    print("$$$$$$$$$$$$$$$$" + str(cloud_mapping))

            data_block = data_block + data_block_temp
            
            data_to_read = data_to_read - (self.block_size_limit)
            #file_offset = 0
            alignment_offset += 1
            # file_offset = 0

        data_block = data_block[file_offset:file_offset+length]

        return data_block.rstrip('\0')

    def write(self, fd, data, offset):
        if fd not in self.fds:
            raise IOError("File descriptor %d does not exist." % fd)
            
        # initialising variables to write
        fill_str = '\0'
        file_offset = offset % self.block_size_limit
        alignment_offset = offset / self.block_size_limit
        data_block = ''
        data_length = len(data)
        backend_offset = self.fds[fd] + '_'

        # checking if there is data already present in the block. If not, add null values of 4096 bytes
        
        #data_block = self.read(fd, self.block_size_limit, hash(backend_offset + str(alignment_offset*self.block_size_limit)))
        data_block = self.read(fd, self.block_size_limit, alignment_offset*self.block_size_limit)
        #print("user data")
        #print(data)
        #print("cloud data")
        #print("offset bu yser")
        #print(offset)
        #print(alignment_offset)
        #print(data_block)
        if data_block == '':
            for i in range(self.block_size_limit):
                data_block += fill_str
        else:
            for i in range(len(data_block), self.block_size_limit):
                data_block += fill_str
        
        data = data_block[0:file_offset] + data
        #loop through and write all data blocks until last block    

        while len(data) + file_offset > self.block_size_limit:
            data_block = (data[0:self.block_size_limit])
            backend_offset_tmp = backend_offset + str(alignment_offset*self.block_size_limit)
            cloud_mapping = self.cloud_storage_mapping(backend_offset_tmp)

            if cloud_mapping == 0:

                self.backends[0].write_block(data_block, str(hash(backend_offset_tmp)))
                self.backends[1].write_block(data_block, str(hash(backend_offset_tmp)))

            elif cloud_mapping == 1:

                self.backends[1].write_block(data_block, str(hash(backend_offset_tmp)))
                self.backends[2].write_block(data_block, str(hash(backend_offset_tmp)))

            else:

                self.backends[2].write_block(data_block, str(hash(backend_offset_tmp)))
                self.backends[0].write_block(data_block, str(hash(backend_offset_tmp)))

            data = data[self.block_size_limit:]
            alignment_offset += 1
            #file_offset = 0
            data_block = ''
        
        
        #Checking if the data is there in the last block
        data_block_last = ''
        '''
        try:
            data_block_last = self.read(fd, self.block_size_limit, alignment_offset*self.block_size_limit)
        except:
            for i in range(self.block_size_limit):
                data_block_last += fill_str
        '''
        data_block_last = self.read(fd, self.block_size_limit, alignment_offset*self.block_size_limit)
        if data_block_last == '':
            for i in range(self.block_size_limit):
                data_block_last += fill_str
        
        # write to the last block
        
        data_block = data + data_block_last[len(data):]
        #for i in range(len(data), self.block_size_limit, 1):
        #    data_block += fill_str
        backend_offset_tmp = backend_offset + str(alignment_offset*self.block_size_limit)
        cloud_mapping = self.cloud_storage_mapping(backend_offset_tmp)

        if cloud_mapping == 0:

            self.backends[0].write_block(data_block, str(hash(backend_offset_tmp)))
            self.backends[1].write_block(data_block, str(hash(backend_offset_tmp)))

        elif cloud_mapping == 1:

            self.backends[1].write_block(data_block, str(hash(backend_offset_tmp)))
            self.backends[2].write_block(data_block, str(hash(backend_offset_tmp)))

        else:

            self.backends[2].write_block(data_block, str(hash(backend_offset_tmp)))
            self.backends[0].write_block(data_block, str(hash(backend_offset_tmp)))    
                
    

    def close(self, fd):
        if fd not in self.fds:
            raise IOError("File descriptor %d does not exist." % fd)

        del self.fds[fd]
        return

    def delete(self, filename):
        # Check in AWS
        # Get list of objects and delete if the filename matches
        backend_offset = filename + '_'
        alignment_offset = 0
        
        while True:
            backend_offset_tmp = backend_offset + str(alignment_offset * self.block_size_limit)
            cloud_mapping = self.cloud_storage_mapping(backend_offset_tmp)
            if cloud_mapping == 0:

                response_delete = self.backends[0].delete_block(str(hash(backend_offset_tmp)))
                if response_delete == 0:
                    break
                
                response_delete = self.backends[1].delete_block(str(hash(backend_offset_tmp)))
                if response_delete == 0:
                    break
                
            elif cloud_mapping == 1:

                response_delete = self.backends[1].delete_block(str(hash(backend_offset_tmp)))
                if response_delete == 0:
                    break
                
                response_delete = self.backends[2].delete_block(str(hash(backend_offset_tmp)))
                if response_delete == 0:
                    break    

            else:

                response_delete = self.backends[2].delete_block(str(hash(backend_offset_tmp)))
                if response_delete == 0:
                    break
                
                response_delete = self.backends[0].delete_block(str(hash(backend_offset_tmp)))
                if response_delete == 0:
                    break
            
            alignment_offset += 1

    def get_storage_sizes(self):
        return 0

