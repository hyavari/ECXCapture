import boto3
import os


def read_aws_sso_profiles():
    # Read AWS CLI configurations including SSO profiles
    session = boto3.Session()
    return session.available_profiles


def get_ecs_clusters(profile_name, regions, cluster_key_name):
    """
    Create an ECS client using boto3 in the specified AWS region.
    
    Parameters:
    - profile_name: AWS CLI named profile to use for authentication.
    - region_name: The AWS region in which the ECS client will be created.
    - cluster_key_name: The key name to look for in the ECS clusters name.
    
    Returns:
    A boto3 ECS client object.
    """
    clusters = {}
    try:
        # Assuming AWS credentials are configured in the environment or via AWS CLI
        session = boto3.Session(profile_name=profile_name)

        # Create an ECS client in the specified region
        for region in regions:
            ecs_client = session.client('ecs', region_name=region)
            clusters[region] = {}
            for cluster in ecs_client.list_clusters()['clusterArns']:
                if cluster_key_name.lower() in cluster.lower():
                    clusters[region][cluster.split("/")[1]] = {} 
                    tasks = ecs_client.list_tasks(cluster=cluster)['taskArns']

                    task_ip_dict = {}
                    for task_arn in tasks:
                        task_details = ecs_client.describe_tasks(cluster=cluster, tasks=[task_arn])['tasks'][0]
                        task_id = task_arn.split('/')[2]
                        task_ip_dict[task_id] = []
                        task_ip_dict[task_id].append(task_details.get('containers', [{}])[0].get('networkInterfaces', [{}])[0].get('privateIpv4Address', 'IPv4 N/A'))
                        task_ip_dict[task_id].append(task_details.get('containers', [{}])[0].get('networkInterfaces', [{}])[0].get('privateIpv6Address', 'IPv6 N/A'))

                    clusters[region][cluster.split("/")[1]]["tasks"] = [task_arn.split('/')[2] for task_arn in tasks]
                    clusters[region][cluster.split("/")[1]]["ipAddresses"] = task_ip_dict

        return clusters
    except Exception as e:
        print(e)
        return None


def get_ec2_instances(profile_name, regions, instance_key_name):
    """
    Get EC2 instances information using boto3.

    Parameters:
    - profile_name: AWS CLI named profile to use for authentication.
    - regions: List of AWS regions to check for EC2 instances.
    - instance_key_name: The key name to look for in the EC2 instances tags.

    Returns:
    A dictionary containing EC2 instances information.
    """
    instances_info = {}

    try:
        # Create a session using the specified AWS CLI profile
        session = boto3.Session(profile_name=profile_name)

        for region in regions:
            # Create an EC2 client in the specified region
            ec2_client = session.client('ec2', region_name=region)
            instances_info[region] = []

            # Describe EC2 instances
            response = ec2_client.describe_instances()
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    for tag in instance['Tags']:
                        if tag['Key'] == 'Name' and instance_key_name in tag['Value']:
                            instance_info = {
                                'InstanceId': instance['InstanceId'],
                                'InstanceName': tag['Value'],
                                'State': instance['State']['Name'],
                                'PrivateIpAddress': instance.get('PrivateIpAddress', 'N/A'),
                            }
                            instances_info[region].append(instance_info)

        return instances_info
    except Exception as e:
        print(f"Error: {e}")
        return None


def get_pcap_from_s3(profile_name, bucket_name, prefix, region_name, local_folder="./"):
    """
    Create an S3 client using boto3 in the specified AWS region.
    
    Parameters:
    - profile_name: AWS CLI named profile to use for authentication.
    - bucket_name: The name of the S3 bucket to upload pcaps.
    - prefix: The name of the pcap file to upload.
    - local_folder: The local folder where the pcap will be downloaded.
    - region_name: The AWS region in which the S3 client will be created.
    
    Returns:
    A boto3 S3 client object.
    """
    try:
        os.makedirs(local_folder, exist_ok=True)
        # Assuming AWS credentials are configured in the environment or via AWS CLI
        session = boto3.Session(profile_name=profile_name, region_name=region_name)

        # Create an S3 client in the specified region
        s3_client = session.client('s3')
        local_path = os.path.join(local_folder, prefix)
        s3_client.download_file(bucket_name, prefix, local_path)
        
        print(f"Downloaded {prefix} to {local_path}")

    except Exception as e:
        print(f"Error listing/Downloading objects in bucket {bucket_name}: {e}")
        print("Check if the machine has permissions to access to the S3 bucket!!")
        return None