import glob
import os
import subprocess
import asyncio
import json
from datetime import datetime


def has_nested_dicts(input_dict):
    return any(isinstance(value, dict) for value in input_dict.values())


def merge_pcap_files_and_open(output_file, input_folder, wireshark_filter='None'):
    input_files = glob.glob(os.path.join(input_folder, '*.pcap'))

    # Check if there are any pcap files in the folder
    if not input_files:
        print(f"No pcap files found in {input_folder}")
        return
    
    mergecap_command = ['mergecap', '-w', output_file, *input_files]
    subprocess.run(mergecap_command)

    wireshark_command = ['wireshark', output_file]

    if wireshark_filter:
        wireshark_command.extend(['-Y', wireshark_filter])

    # Check if the output file was created
    if os.path.exists(output_file):
        subprocess.run(wireshark_command)
    else:
        print(f"Error: Failed to create {output_file}")


async def run_ecs_command(region, sso_profile, cluster_name, task_id, cmd):
    process = subprocess.Popen(
        ["aws", "ecs", "execute-command",
        "--cluster", cluster_name,
        "--task", task_id,
        "--command", cmd,
        "--interactive",
        "--region", region,
        "--profile", sso_profile],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0,
    )
    return process


async def run_ec2_command(region, sso_profile, instance_id, cmd):
    process = subprocess.Popen(
        ["aws", "ssm", "send-command",
        "--instance-ids", instance_id,
        '--document-name', 'AWS-RunShellScript',
        '--parameters', f"commands='{cmd}'",
        "--region", region,
        "--profile", sso_profile],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0,
    )
    return process


def stop_command(process):
    try:
        if os.name == 'posix':
            process.terminate()  # Send interrupt signal (Ctrl+C) to stop command
        else:
            process.kill()
    except asyncio.CancelledError as e:
        print(f"Error stopping command: {e}")
        pass  # Ignore CancelledError when the process is terminated


def read_config(config_file_path):
    try:
        with open(config_file_path, 'r') as file:
            config_data = json.load(file)
        return config_data
    except FileNotFoundError:
        print(f"Config file not found: {config_file_path}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON in config file: {e}")
        return None


def get_sso_session_expiration():
    # Read the AWS CLI session file to get SSO session information
    sso_cache_dir = os.path.expanduser('~/.aws/sso/cache')

    # Filter only JSON files in the directory
    json_files = [f for f in os.listdir(sso_cache_dir) if f.endswith('.json')]

    if not json_files:
        return None  # No JSON files found

    # Get the latest created JSON file
    latest_json_file = max(json_files, key=lambda f: os.path.getmtime(os.path.join(sso_cache_dir, f)))
    session_file_path = os.path.join(sso_cache_dir, latest_json_file)

    try:
        with open(session_file_path, 'r') as session_file:
            session_info = session_file.read()
            session_info = json.loads(session_info)
            if 'startUrl' not in session_info:
                return None
            expiration_time_str = session_info['expiresAt']
            expiration_time = datetime.strptime(expiration_time_str, "%Y-%m-%dT%H:%M:%SZ")
            return expiration_time
    except (FileNotFoundError, KeyError, json.JSONDecodeError):
        return None


def create_sso_session(profile_name):
    # Use AWS CLI's 'aws sso login' command to create an SSO session
    subprocess.run(['aws', 'sso', 'login', '--profile', profile_name])
