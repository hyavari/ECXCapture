from utils.aws_services import *
from utils.common import *
import json
import asyncio
from datetime import datetime


textArt = """
    _____________  ________            __                
   / ____/ ____/ |/ / ____/___ _____  / /___  __________ 
  / __/ / /    |   / /   / __ `/ __ \/ __/ / / / ___/ _ |
 / /___/ /___ /   / /___/ /_/ / /_/ / /_/ /_/ / /  /  __/
/_____/\____//_/|_\____/\__,_/ .___/\__/\__,_/_/   \___/ 
                            /_/     

        """

CYELLOW = '\33[33m'
CGREEN  = '\33[32m'
CRED    = '\33[31m'
CBLUE   = '\33[34m'
CEND    = '\33[0m'
config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config/config.json")
DEFAULT_PCAP_DIR = "./Pcaps/"
LAB_REGIONS = ["us-east-1"]
PROD_REGIONS = ["us-east-2", "us-west-2"]
WIRESHARK_FILTERS = 'sip || esp || rtcp || rtp'

# Commands
TCP_DUMP_ECS_COMMAND = "tcpdump -i any port not 22 -U -s0 -w ./pcapScript/tcpdump_{task_id}.pcap"
MV_PCAP_TO_S3_ECS_COMMAND = "/root/.nvm/versions/node/v16.19.0/bin/node ./pcapScript/savePcap.js ./pcapScript/tcpdump_{task_id}.pcap"
TCP_DUMP_EC2_COMMAND = "sudo tcpdump -i any port not 22 -U -s0 -w /home/ec2-user/tcpdump_{instance_id}.pcap"
TCP_DUMP_EC2_STO_AND_3MV_COMMAND = "sudo pkill tcpdump && sudo aws s3 cp /home/ec2-user/tcpdump_{instance_id}.pcap s3://{bucket_name}/tcpdump_{instance_id}.pcap"
ECS_CONNECTION_COMMAND = 'aws ecs execute-command --region {region} --profile {sso_profile} --cluster {cluster} --task {task_id} --command "/bin/bash" --interactive'


async def main():
    print(CRED + textArt + CEND)
    print(CYELLOW + "Welcome to ECXCapture!" + "\U0001F40D" + CEND)
    print("It is a tool to capture your ECS/EC2 traffic in one place.")
    print("===============================================")
    print("===============================================")

    ########################################## CONFIG FILE
    config_data = read_config(config_file_path)

    if not config_data:
        print(CRED + "Config file not found or invalid. Exiting..." + CEND)
        exit(1)


    ########################################## SSO PROFILE
    # Read available AWS SSO profiles
    sso_profiles = read_aws_sso_profiles()

    if not sso_profiles:
        print(CRED + "No AWS SSO profiles found !" + CEND)
        return
    else:
        print(CGREEN + f"<== Found {len(sso_profiles)} AWS SSO profiles ==>" + CEND)

    # Prompt user to select a profile
    print("\nAvailable AWS SSO Profiles: ")
    for i, profile in enumerate(sso_profiles, start=1):
        print(f"{i}.{profile}")
    
    while True:
        selection = input("\nWhich profile you want to use? (default: [1]) ")

        if not selection:
            # If the user presses Enter without providing a selection, use the default
            selected_profile = sso_profiles[0]
            break

        try:
            if int(selection) < 1 or int(selection) > len(sso_profiles):
                raise ValueError
            selection_index = int(selection) - 1
            selected_profile = sso_profiles[selection_index]
            break  # Break the loop if a valid selection is made
        except (ValueError, IndexError):
            print(CRED + "Invalid selection! Please enter a valid profile number." + CEND)


    # Check if the SSO session is expired
    expiration_time = get_sso_session_expiration()

    if expiration_time and expiration_time > datetime.utcnow():
        print("SSO session for profile " + CGREEN + f"'{selected_profile}'" + CEND + " is still valid. No need to log in.")
    else:
        # Create an SSO session for the selected profile
        create_sso_session(selected_profile)
        print(CGREEN + f"SSO session created for the profile: {selected_profile}" + CEND)


    ########################################## AWS ENVIRONMENT
    # Which environment to capture?
    if "lab" in selected_profile.lower():
        env = "lab"
    elif "prod" in selected_profile.lower():
        env = "prod"
    else:
        print("\nAvailable environments: ")
        print("1. Lab")
        print("2. Prod")

        while True:
            env_input = input("\nWhich environment you want to capture? (default: [1]) ")

            try:
                if not env_input:
                    env = "lab"
                    break

                if int(env_input) < 1 or int(env_input) > 2:
                    raise ValueError
                env = "lab" if int(env_input) == 1 else "prod"
                break  # Break the loop if a valid selection is made
            except (ValueError, IndexError):
                print(CRED + "Invalid selection! Please enter a valid number." + CEND)


    selected_regions = config_data.get("regions", {}).get(env)
    print("Configured regions for selected env: " + CGREEN + f"{selected_regions}" + CEND)


    ########################################## List all services that we can capture from config file
    print("\nAvailable capture types: ")
    for i, service_name in enumerate(config_data.get("captureServices", {}), start=1):
        print(f"{i}. {service_name}")

    while True:
        service_type_input = input("\nWhich one you want to capture? (default: [1]) ")

        try:
            if not service_type_input:
                service_type = 1
                break

            if int(service_type_input) < 1 or int(service_type_input) > len(config_data.get("captureServices", {})):
                raise ValueError
            service_type = int(service_type_input)             
            break  # Break the loop if a valid selection is made
        except (ValueError, IndexError):
            print(CRED + "Invalid selection! Please enter a valid number." + CEND)

    service_config = list(config_data.get("captureServices", {}).keys())[service_type - 1]  
    
    if not service_config:
        print(CRED + "No service config found !" + CEND)
        return
    
    # Check if the selected service has nested dicts
    sub_service_config = config_data["captureServices"][service_config]

    if has_nested_dicts(sub_service_config):
        print("\nAvailable services: ")
        for i, service in enumerate(sub_service_config, start=1):
            print(f"{i}.{service}")

        while True:
            service_input = input("\nWhich service you want to capture? (default: [1]) ")

            try:
                if not service_input:
                    service = list(sub_service_config.keys())[0]
                    break

                if int(service_input) < 1 or int(service_input) > len(sub_service_config):
                    raise ValueError
                service = list(sub_service_config.keys())[int(service_input) - 1]
                sub_service_config = config_data["captureServices"][service_config][service]
                break  # Break the loop if a valid selection is made
            except (ValueError, IndexError):
                print(CRED + "Invalid selection! Please enter a valid number." + CEND)
    else:
        service = service_config    

    print("Selected service: " + CGREEN + f"'{service}'" + CEND + 
          ", Server type: " + CGREEN + f"'{sub_service_config.get('type').upper()}'" + CEND)    
    print("===============================================")
    server_type = sub_service_config.get("type").lower()


    ########################################## ECS Services Capture
    if server_type == 'ecs':
        ecs_clusters = get_ecs_clusters(selected_profile, selected_regions, sub_service_config.get("id"))

        if not ecs_clusters:
            print(CRED + "No ECS clusters found !" + CEND)
            return

        print("Available ECS clusters for selected service: \n" + CGREEN +  f"{json.dumps(ecs_clusters, indent=2)}" + CEND)

        print("\nAvailable actions: ")
        print("1. Tcpdump capture")
        print("2. Connectiong to the instances commands")

        while True:
            action_input = input("\nWhich action you want to do? (default: [1]) ")

            try:
                if not action_input:
                    action = 1
                    break

                if int(action_input) < 1 or int(action_input) > 2:
                    raise ValueError
                action = int(action_input)
                break  # Break the loop if a valid selection is made
            except (ValueError, IndexError):
                print(CRED + "Invalid selection! Please enter a valid number." + CEND)


        if action == 1:
            input(CYELLOW + "======> Ready to start capture? Press Enter to continue..." + CEND)

            running_processes = []
            task_ids = []

            # Start tcpdump on each task
            for region, clusters in ecs_clusters.items():
                for cluster_name, cluster_info in clusters.items():
                    for task_id in cluster_info.get("tasks", []):
                        # Run tcpdump on each task in the background
                        process = await run_ecs_command(region, selected_profile, cluster_name, task_id, TCP_DUMP_ECS_COMMAND.format(task_id=task_id))
                        running_processes.append(process)
                        task_ids.append(task_id)

            if not running_processes:
                print(CRED + "No ECS tasks found !" + CEND)
                return
            else:
                print(CGREEN + f"Started {len(running_processes)} tcpdump sessions..." + CEND)

            # Allow the user to stop tcpdump sessions when desired
            while True:
                user_input = input("Type" + CYELLOW + " 'stop' " + CEND + "to stop tcpdump sessions: ").strip()
                if user_input.lower() == "stop":
                    break
                else:
                    print("Invalid input !\n")
                
            for process in running_processes:
                stop_command(process)
            
            print(CGREEN + "Stopped all tcpdump sessions." + CEND)
            

            ########################################## S3 BUCKET DOWNLOAD PCAPs
            print(CYELLOW + "Please wait while the script is downloading the pcap files..." + CEND)

            # Move the pcap files to S3
            for region, clusters in ecs_clusters.items():
                for cluster_name, cluster_info in clusters.items():
                    for task_id in cluster_info.get("tasks", []):
                        process = await run_ecs_command(region, selected_profile, cluster_name, task_id,
                                                            MV_PCAP_TO_S3_ECS_COMMAND.format(task_id=task_id))
                        process.wait()
            
            # Download the pcap files from S3
            pcaps_folder_path = DEFAULT_PCAP_DIR + f"{service}/" + env + f"/{datetime.now().strftime('%Y-%m-%d-%H-%M')}/"
            
            for task_id in task_ids:
                get_pcap_from_s3(selected_profile, config_data.get("buckets", {}).get(env, {}).get("name"), f"tcpdump_{task_id}.pcap", 
                                 config_data.get("buckets", {}).get(env, {}).get("region"), pcaps_folder_path)
                
            
            print(CGREEN + "Downloaded all pcap files. Opening the merged pcap in Wireshark..." + "\U0001F680" + CEND)
            # Merge the pcap files and open in Wireshark
            merge_pcap_files_and_open(pcaps_folder_path + f"{service}.pcap", pcaps_folder_path, WIRESHARK_FILTERS)
        elif action == 2:
            for region, clusters in ecs_clusters.items():
                for cluster_name, cluster_info in clusters.items():
                    for task_id in cluster_info.get("tasks", []):
                        print(CYELLOW + ECS_CONNECTION_COMMAND.format(region=region, sso_profile=selected_profile, cluster=cluster_name, task_id=task_id) + CEND)
    
    ########################################## EC2 Services Capture
    else:
        # Get EC2 instances information
        ec2_instances = get_ec2_instances(selected_profile, selected_regions, sub_service_config.get("id"))

        if not ec2_instances:
            print(CRED + "No EC2 instances found !" + CEND)
            return

        print("Available EC2 instances for selected service: \n" + CGREEN + f"{json.dumps(ec2_instances, indent=2)}" + CEND)
        
        input(CYELLOW + "======> Ready to start capture? Press Enter to continue..." + CEND)

        running_processes = []
        instance_ids = []
        # Start tcpdump on each instance
        for region, instances in ec2_instances.items():
            for instance in instances:
                # Run tcpdump on each instance in the background
                process = await run_ec2_command(region, selected_profile, instance.get("InstanceId"), TCP_DUMP_EC2_COMMAND.format(instance_id=instance.get("InstanceId")))
                process.wait()
                running_processes.append(process)

        print(CGREEN + f"Started {len(running_processes)} tcpdump sessions..." + CEND)

        # Allow the user to stop tcpdump sessions when desired
        while True:
            user_input = input("Type" + CYELLOW + " 'stop' " + CEND + "to stop tcpdump sessions: ").strip()
            if user_input.lower() == "stop":
                break
            else:
                print("Invalid input !\n")

        # Stop tcpdump on each instance and move the pcap file to S3
        for region, instances in ec2_instances.items():
            for instance in instances:
                # Stop tcpdump and move the pcap file to S3
                process = await run_ec2_command(region, selected_profile, instance.get("InstanceId"), TCP_DUMP_EC2_STO_AND_3MV_COMMAND.format(instance_id=instance.get("InstanceId"), bucket_name=config_data.get("buckets", {}).get("lab" if env == 1 else "prod")))
                process.wait()
                instance_ids.append(instance.get("InstanceId"))


        # Download the pcap files from S3
        pcaps_folder_path = DEFAULT_PCAP_DIR + f"{service}/" + env + f"/{datetime.now().strftime('%Y-%m-%d-%H-%M')}/"
        
        for instance_id in instance_ids:
            get_pcap_from_s3(selected_profile, config_data.get("buckets", {}).get(env, {}).get("name"), f"tcpdump_{instance_id}.pcap",
                              config_data.get("buckets", {}).get(env, {}).get("region"), pcaps_folder_path)
            
        print(CGREEN + "Downloaded all pcap files. Opening the merged pcap in Wireshark..." + "\U0001F680" + CEND)

        # Merge the pcap files and open in Wireshark
        merge_pcap_files_and_open(pcaps_folder_path + f"{service}.pcap", pcaps_folder_path, WIRESHARK_FILTERS)

    print(CGREEN + "Thank you for using this tool!" + CEND + "\U0001F31F")


if __name__ == "__main__":
    asyncio.run(main())