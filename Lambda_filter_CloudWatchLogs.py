
### Code: Lambda function to filter ec2, s3 and vpc events.
### Author: Nitin Sharma
### SDK: Python 3.6 boto3
### More info: Refer to 4hathacker.in


import json
import base64
import gzip
import boto3
import zlib
import base64
from datetime import datetime
from io import StringIO
import ast
import random
print('Loading function')


def lambda_handler(event, context):
    
    # ---------------------
    # Seed generation and timestamp generation for unique file name
    random.seed()
    curr_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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
        "s3":("CreateBucket","DeleteBucket","DeleteBucketCors","DeleteBucketEncryption","DeleteBucketLifecycle","DeleteBucketPolicy","DeleteBucketReplication","DeleteBucketTagging","DeleteBucketWebsite","PutBucketAcl","PutBucketCors","PutBucketEncryption","PutBucketLifecycle","PutBucketLogging","PutBucketNotification","PutBucketPolicy","PutBucketReplication","PutBucketRequestPayment","PutBucketTagging","PutBucketVersioning","PutBucketWebsite")
    }
    # ---------------------
    
    # ---------------------
    # Creating S3 boto3 client
    client = boto3.client('s3')
    # ---------------------
    
    # ----------------------
    # Filtering the events and saving in respective folders in s3 bucket
    for i in cleanLog:
        evName = ((json.loads(i["message"]))["eventName"])
        for k,v in services.items():
                if v.count(evName) > 0:
                    key = k + '/' + evName + '_' + curr_time + "_" + str(random.random()).replace('.','') + ".json"
                    response = client.put_object(Body=json.dumps(json.loads(i["message"])), Bucket='all-logs-filtered-123', Key=key)
                    break
    # -----------------------
    
    
            
