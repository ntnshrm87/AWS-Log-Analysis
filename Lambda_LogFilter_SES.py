### Code     : Lambda function to filter important log events
### Author   : Nitin Sharma
### SDK      : Python 3.6 boto3
### Functions:
### 1. Collect logs from Master log bucket in S3.
### 2. Filter important log events and save them in respective bucket folders.
### 3. Send mail to Security / Incident Response team for critical events from IT Side.

import re
import os
import json
import base64
import gzip
import boto3
import zlib
import base64
from datetime import datetime
from io import StringIO
import random
from botocore.exceptions import ClientError
print('Loading function')


def lambda_handler(event, context):
    
    # ---------------------
    # Seed generation and timestamp generation for unique file name
    random.seed()
    curr_time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
    # ---------------------
    
    # ---------------------
    # All log events in encrypted format and deciphering it 
    outEvent = str(event['awslogs']['data'])
    outEvent = zlib.decompress(base64.b64decode(outEvent), 16 + zlib.MAX_WBITS).decode('utf-8')
    # print (outEvent)
    # ---------------------
    
    # ---------------------
    # Extracting list of log-events
    cleanEvent = json.loads(outEvent)
    cleanLog=cleanEvent['logEvents']
    # print (cleanLog)
    # ---------------------
    
    
    # ---------------------
    # Declaring filter event names in services dictionary
    services = {
        "vpc":("CreateVpc","CreateVpcEndpoint","CreateVpcPeeringConnection","CreateVpcPeeringAuthorization","CreateVpcPeeringConnection","CreateVpcLink","CreateDefaultVpc","DeleteVpc","DeleteVpcEndpoints","DeleteVpcPeeringConnection","DeleteVpcPeeringAuthorization","DeleteVpcPeeringConnection","DeleteVpcLink","UpdateVpcLink","ModifyVpcAttribute","ModifyVpcEndpoint","AcceptVpcPeeringConnection","AssociateVpcCidrBlock","AttachClassicLinkVpc","DetachClassicLinkVpc","DisableVpcClassicLink","DisassociateVpcCidrBlock","EnableDefaultTenancyForVpc","EnableVpcClassicLink","MoveAddressToVpc","RejectVpcPeeringConnection","AssociateVPCWithHostedZone","DisassociateVPCFromHostedZone"),
        "ec2":("RunInstances", "RebootInstances", "StartInstances", "StopInstances", "TerminateInstances","CreateCustomerGateway","CreateDefaultSubnet","CreateVpnGateway","CreateDhcpOptions","CreateEgressOnlyInternetGateway","CreateImage","CreateInstanceExportTask","CreateInternetGateway","CreateKeyPair","CreateNatGateway","CreateNetworkAcl","CreateNetworkAclEntry","CreateNetworkInterface","CreatePlacementGroup","CreateReservedInstancesListing","CreateRoute","CreateRouteTable","CreateSnapshot","CreateSpotDatafeedSubscription","CreateVpnConnectionRoute","CreateSubnet","CreateTags","CreateVolume","CreateVpnConnection","DeleteCustomerGateway","DeleteVpnGateway","DeleteDhcpOptions","DeleteEgressOnlyInternetGateway","DeleteInternetGateway","DeleteKeyPair","DeleteNatGateway","DeleteNetworkAcl","DeleteNetworkAclEntry","DeleteNetworkInterface","DeletePlacementGroup","DeleteRoute","DeleteRouteTable","DeleteVpnConnectionRoute","DeleteSnapshot","DeleteSpotDatafeedSubscription","DeleteSubnet","DeleteTags","DeleteVolume","DeleteVpnConnection","DeleteVpnConnectionRoute","ModifyHosts","ModifyIdentityIdFormat","ModifyImageAttribute","ModifyInstanceAttribute","ModifyInstancePlacement","ModifyNetworkInterfaceAttribute","ModifyReservedInstances","ModifySnapshotAttribute","ModifySubnetAttribute","ModifyVolume","ModifyVolumeAttribute","AcceptReservedInstancesExchangeQuote","AcceptVpcPeeringConnection","AllocateAddress","AllocateHosts","AssignIpv6Addresses","AssignPrivateIpAddresses","AssociateAddress","AssociateDhcpOptions","AssociateIamInstanceProfile","AssociateRouteTable","AssociateSubnetCidrBlock","AssociateVpcCidrBlock","AttachClassicLinkVpc","AttachInternetGateway","AttachNetworkInterface","AttachVolume","AttachVpnGateway","AuthorizeSecurityGroupEgress","AuthorizeSecurityGroupIngress","BundleInstance","CancelBundleTask","CancelConversionTask","CancelExportTask","CancelImportTask","CancelReservedInstancesListing","CancelSpotInstanceRequests","CopyImage","CopySnapshot","DeregisterImage","DetachClassicLinkVpc","DetachInternetGateway","DetachNetworkInterface","DetachVolume","DetachVpnGateway","DisableVgwRoutePropagation","DisableVpcClassicLink","DisassociateAddress","DisassociateIamInstanceProfile","DisassociateRouteTable","DisassociateSubnetCidrBlock","DisassociateVpcCidrBlock","EnableDefaultTenancyForVpc","EnableVgwRoutePropagation","EnableVolumeIO","EnableVpcClassicLink","ImportImage","ImportInstance","ImportKeyPair","ImportSnapshot","ImportVolume","DeregisterImage","DetachClassicLinkVpc","DetachInternetGateway","DetachNetworkInterface","DetachVolume","DetachVpnGateway","DisableVgwRoutePropagation","DisableVpcClassicLink","DisassociateAddress","DisassociateIamInstanceProfile","DisassociateRouteTable","DisassociateSubnetCidrBlock","DisassociateVpcCidrBlock","EnableDefaultTenancyForVpc","EnableVgwRoutePropagation","EnableVolumeIO","EnableVpcClassicLink","ImportImage","ImportInstance","ImportKeyPair","ImportSnapshot","ImportVolume"),
        "s3":("CreateBucket","DeleteBucket","DeleteBucketCors","DeleteBucketEncryption","DeleteBucketLifecycle","DeleteBucketPolicy","DeleteBucketReplication","DeleteBucketTagging","DeleteBucketWebsite","PutBucketAcl","PutBucketCors","PutBucketEncryption","PutBucketLifecycle","PutBucketLogging","PutBucketNotification","PutBucketPolicy","PutBucketReplication","PutBucketRequestPayment","PutBucketTagging","PutBucketVersioning","PutBucketWebsite"),
        "cloudtrail":("CreateTrail","DeleteTrail","PutEventSelectors","AddTags","RemoveTags","StartLogging","StopLogging","UpdateTrail"),
        "securitygroup":("CreateSecurityGroup","CreateDBSecurityGroup","DeleteSecurityGroup","DeleteDBSecurityGroup","AuthorizeSecurityGroupEgress","AuthorizeSecurityGroupIngress","RevokeSecurityGroupEgress","RevokeSecurityGroupIngress","ApplySecurityGroupsToLoadBalancer","SetSecurityGroups","AuthorizeDBSecurityGroupIngress","RevokeDBSecurityGroupIngress"),
        "loginevents":("ConsoleLogin")  
    }
    # ---------------------
    
    # ---------------------
    # Critical Event filters for SES Notification
    critical_buckets = ("all-logs-bucket123", "all-logs-filtered-123")
    critical_trails = ("all-logs-trail123")
    c_event = {
        1: "Root Account activities found.",
        2: "Important Log trail deleted.",
        3: "Important Log bucket deleted."
    }
    # ---------------------
    
    # ---------------------
    # Creating S3 boto3 client
    client = boto3.client('s3')
    # ---------------------
    
    # -----------------------
    # SENDER    : Email must be sent by IT-Team 
    # RECIPIENT : Email sent to Incident Response Team or Security Team
    # AWS-Region: Check with AWS SES documentation as its functional in three regions only
    
    SENDER = "IT Team <ntnshrm87@gmail.com>"
    RECIPIENT = "ntnshrm28@gmail.com"
    AWS_REGION = "us-east-1"
    # ----------------------
    
    # ----------------------
    # Filtering the events and saving in respective folders in s3 bucket
    for i in cleanLog:
        c_flag = 0
        
        # Case 1:
        if ((json.loads(i["message"]))["userIdentity"]["type"]) == "Root":
            c_flag = 1
        
        evName = ((json.loads(i["message"]))["eventName"])
        
        # Case 2:
        if evName == "DeleteBucket" and  ((json.loads(i["message"]))["requestParameters"]["bucketName"]) in critical_buckets:
            print(((json.loads(i["message"]))["requestParameters"]["bucketName"]))
            c_flag = 3
            
        # Case 3:
        if evName == "DeleteTrail":
            t_name = ((json.loads(i["message"]))["requestParameters"]["name"])
            print(t_name)
            if len([x for x in critical_trails if re.search(x,t_name)]):
                c_flag = 2
        
        # If c_flag raised
        if c_flag != 0:
            
            # -----------------------
            # Subject of mail as per incident
            SUBJECT = "AWS_Security_Incident: " + c_event[c_flag]
            # -----------------------

            # -----------------------
            # The email body for recipients with non-HTML email clients.
            BODY_TEXT = ("Security Incident Logged in AWS \r\n"
                         "Kindly check the secure logs location."
                        )
            # -----------------------
    
            # -----------------------
            # The email body for recipients with HTML email clients.
            BODY_HTML = """<html>
            <head></head>
            <body>
              <h1>AWS_Security_Incident</h1>
              <p>
                  Security Incident Logged in AWS. 
                  Kindly check the secure logs location.
              </p>
            </body>
            </html>
                    """   
            # -----------------------
    
            # -----------------------
            # The character encoding for the email.
            CHARSET = "UTF-8"
            # -----------------------
            
            # -----------------------
            # Create a new SES resource and specify a region.
            ses_client = boto3.client('ses',region_name=AWS_REGION)
            # -----------------------
        
            # -----------------------
            # Try to send the email.
            try:
                #Provide the contents of the email.
                response = ses_client.send_email(
                    Destination={
                        'ToAddresses': [
                            RECIPIENT,
                        ],
                    },
                    Message={
                        'Body': {
                            'Html': {
                                'Charset': CHARSET,
                                'Data': BODY_HTML,
                            },
                            'Text': {
                                'Charset': CHARSET,
                                'Data': BODY_TEXT,
                            },
                        },
                        'Subject': {
                            'Charset': CHARSET,
                            'Data': SUBJECT,
                        },
                    },
                    Source=SENDER,
                )
            except ClientError as e:
                print(e.response['Error']['Message'])
            else:
                print("Email sent! Message ID:"),
                print(response['MessageId'])
            # -----------------------
        
        # ---------------------
        # Saving filtered logs in S3
        for k,v in services.items():
                if v.count(evName) > 0:
                    key = k + '/' + evName + '_' + curr_time + "_" + str(random.random()).replace('.','') + ".json.gz"
                    gzipper = gzip.open('/tmp/data2gz.gz', 'wb')
                    gzipper.write((json.dumps(json.loads(i["message"]))).encode('utf-8')) 
                    gzipper.close()
                    client.upload_file('/tmp/data2gz.gz','all-logs-filtered-123', key)
                    if os.path.exists('/tmp/data2gz.gz'):
                        os.remove('/tmp/data2gz.gz')
                    # response = client.put_object(Body=json.dumps(json.loads(i["message"])), Bucket='all-logs-filtered-123', Key=key)
                    break
        # ---------------------
    
    # -----------------------
    
    
            
