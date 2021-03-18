from basic_defs import cloud_storage, NAS
from credentials import aws_credentials, gcp_credentials, azure_credentials

import boto3
from azure.storage.blob import BlobServiceClient
from google.cloud import storage

import os
import sys

class AWS_S3(cloud_storage):
    def __init__(self):
        # TODO: Fill in the AWS access key ID
        #self.access_key_id = aws_credentials.access_key_id
        # TODO: Fill in the AWS access secret key
        #self.access_secret_key = aws_credentials.access_secret_key
        # TODO: Fill in the bucket name
        #self.bucket_name = aws_credentials.bucket_name
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
        # To be Implemented
        pass

    def write_block(self, block, offset):
        # To be Implemented
        pass

    def delete_block(self, offset):
        # To be Implemented
        pass

class Azure_Blob_Storage(cloud_storage):
    def __init__(self):
        # TODO: Fill in the Azure key
        #self.key = azure_credentials.key
        # TODO: Fill in the Azure connection string
        #self.conn_str = azure_credentials.conn_str
        # TODO: Fill in the account name
        #self.account_name = "csce678s21"
        # TODO: Fill in the container name
        #self.container_name = azure_credentials.container_name
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
        # To be Implemented
        pass

    def write_block(self, block, offset):
        # To be Implemented
        pass

    def delete_block(self, offset):
        # To be Implemented
        pass

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

    # Implement the abstract functions from NAS
    def open(self, filename):
        # To be Implemented
        pass

    def read(self, fd, len, offset):
        # To be Implemented
        pass

    def write(self, fd, data, offset):
        # To be Implemented
        pass

    def close(self, fd):
        # To be Implemented
        pass

    def delete(self, filename):
        # To be Implemented
        pass

    def get_storage_sizes(self):
        return 0

