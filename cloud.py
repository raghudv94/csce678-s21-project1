from basic_defs import cloud_storage, NAS
from credentials import aws_credentials, gcp_credentials, azure_credentials

import boto3
from azure.storage.blob import BlobServiceClient
from google.cloud import storage

import os
import sys
import re

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
        return self.aws_bucket.objects.all()

    def read_block(self, offset):
        return self.s3.Object(self.bucket_name, offset).get()['Body'].read()

    def write_block(self, block, offset):
        self.s3.Object(self.bucket_name, offset).put(Body=block)

    def delete_block(self, offset):
        self.s3.Object(self.bucket_name, offset).delete()

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
        return self.azure_bucket.list_blobs()

    def read_block(self, offset):
        return self.azure_service_client.get_blob_client(container=self.container_name, blob=offset).download_blob().readall()

    def write_block(self, block, offset):
        self.azure_service_client.get_blob_client(container=self.container_name, blob=offset).upload_blob(block)

    def delete_block(self, offset):
        self.azure_service_client.get_blob_client(container=self.container_name, blob=offset).delete_blob()

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
        return self.gcp_storage_client.list_blobs(self.gcp_bucket)

    def read_block(self, offset):
        # To be Implemented
        pass

    def write_block(self, block, offset):
        # To be Implemented
        pass

    def delete_block(self, offset):
        # To be Implemented
        pass

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
    def cloud_storage_mapping(filename_tmp):
        return int(hashlib.md5(filename_tmp).hexdigest(), base=16) % 3

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
        return newfd

    def read(self, fd, len, offset):
        if fd not in self.fds:
            raise IOError("File descriptor %d does not exist." % fd)
            
        # Initialising variables to read
        file_offset = offset % 4096
        alignment_offset = offset / 4096
        backend_offset = self.fds[fd] + '_'
        data_block = ''
        data_to_read = len

        # Start reading  from first block till last but one block
        while data_to_read + file_offset > self.block_size_limit:
            backend_offset_tmp = backend_offset + str(alignment_offset*4096)
            cloud_mapping = self.cloud_storage_mapping(backend_offset)
            if cloud_mapping == 0:

                data_block_temp = self.backends[0].read_block(backend_offset_tmp)

            elif cloud_mapping == 1:

                data_block_temp = self.backends[1].read_block(backend_offset_tmp)

            else:

                data_block_temp = self.backends[2].read_block(backend_offset_tmp)

            data_block = data_block + data_block_temp[file_offset:]
            data_to_read = data_to_read - (self.block_size_limit - file_offset)
            alignment_offset += 1
            file_offset = 0

        # Read the last block
        backend_offset_tmp = backend_offset + str(alignment_offset*4096)
        cloud_mapping = self.cloud_storage_mapping(backend_offset)
        if cloud_mapping == 0:

            data_block_temp = self.backends[0].read_block(backend_offset_tmp)

        elif cloud_mapping == 1:

            data_block_temp = self.backends[1].read_block(backend_offset_tmp)

        else:

            data_block_temp = self.backends[2].read_block(backend_offset_tmp)

        data_block = data_block + data_block_temp[:data_to_read]

        return data_block

    def write(self, fd, data, offset):
        if fd not in self.fds:
            raise IOError("File descriptor %d does not exist." % fd)
            
        # initialising variables to write
        fill_str = '\0'
        file_offset = offset % 4096
        alignment_offset = offset / 4096
        data_block = ''
        data_length = len(data)
        backend_offset = self.fds[fd] + '_'

        # checking if there is data already present in the block. If not, add null values of 4096 bytes
        try:
            data_block = self.read(fd, self.block_size_limit, alignment_offset*4096)
        except:
            for i in range(self.block_size_limit):
                data_block += fill_str
                
        #loop through and write all data blocks until last block    

        while len(data) > self.block_size_limit:
            data_block = data_block[:file_offset] + data[:self.block_size_limit - file_offset]
            backend_offset_tmp = backend_offset + str(alignment_offset*4096)
            cloud_mapping = self.cloud_storage_mapping(backend_offset_tmp)

            if cloud_mapping == 0:

                self.backends[0].write_block(data_block, backend_offset_tmp)
                self.backends[1].write_block(data_block, backend_offset_tmp)

            elif cloud_mapping == 1:

                self.backends[1].write_block(data_block, backend_offset_tmp)
                self.backends[2].write_block(data_block, backend_offset_tmp)

            else:

                self.backends[2].write_block(data_block, backend_offset_tmp)
                self.backends[0].write_block(data_block, backend_offset_tmp)

            data = data[self.block_size_limit - file_offset:]
            alignment_offset += 1
            file_offset = 0
            data_block = ''

        # write to the last block
        data_block = data
        for i in range(len(data), self.block_size_limit, 1):
            data_block += fill_str

        backend_offset_tmp = backend_offset + str(alignment_offset*4096)
        cloud_mapping = self.cloud_storage_mapping(backend_offset_tmp)

        if cloud_mapping == 0:

            self.backends[0].write_block(data_block, backend_offset_tmp)
            self.backends[1].write_block(data_block, backend_offset_tmp)

        elif cloud_mapping == 1:

            self.backends[1].write_block(data_block, backend_offset_tmp)
            self.backends[2].write_block(data_block, backend_offset_tmp)

        else:

            self.backends[2].write_block(data_block, backend_offset_tmp)
            self.backends[0].write_block(data_block, backend_offset_tmp)    
                
    

    def close(self, fd):
        if fd not in self.fds:
            raise IOError("File descriptor %d does not exist." % fd)

        del self.fds[fd]
        return

    def delete(self, filename):
        # Check in AWS
        # Get list of objects and delete if the filename matches
        for block in self.backends[0].list_blocks():
            if filename == re.match(r'(.*)_\d+$', block.key).group(1):
                self.backends[0].delete_block(block.key)
                
        # Check in Azure
        #Get list of objects and delete if the filename matches
        for block in self.backends[1].list_blocks():
            if filename == re.match(r'(.*)_\d+$', block.name).group(1):
                self.backends[1].delete_block(block.name)
                

        # Check in Google
        #Get list of objects and delete if the filename matches
        for block in self.backends[2].list_blocks():
            if filename == re.match(r'(.*)_\d+$', block.name).group(1):
                self.backends[2].delete_block(block.name)

    def get_storage_sizes(self):
        return 0

