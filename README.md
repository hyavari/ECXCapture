# ECXCapture
A user-friendly tool for effortless capturing of AWS ECS/EC2 network interfaces, simplifying your networking tasks.


## Features
- ✅ ECS Clusters Capturing
- ✅ EC2 Instances Capturing

## Usage

1. Clone the repository:
    ```bash
    git clone https://github.com/hyavari/ECXCapture
    ```
2. Navigate to the `ECXCapture` directory:
    ```bash
    cd {path}/ECXCapture
    ```
3. Install the requirements:
    ```bash
    pip install -r requirements.txt
    ```
4. Update the config file (`config/config.js`) based on your AWS settings. The config.js file is structured into three main sections:

    #### Regions:

    Define regions for different environments such as "lab" and "prod." Each region includes an array of AWS regions.

    **Example:**

    ``` json
    "regions": {
        "lab": ["ca-central-1"],
        "prod": ["us-east-2", "us-west-2"]
    },
    ```

    #### Buckets:

    Define S3 buckets for each environment. Each bucket includes a name and the AWS region where it is located.

    **Example:**

    ```json
    "buckets": {
        "lab": {
            "name": "capture-pcaps-lab",
            "region": "us-east-1"
        },
        "prod": {
            "name": "capture-pcaps-prod",
            "region": "us-east-2"
        }
    },
    ```
    #### Capture Services:

    Define capture services categorized by type (e.g., "SIP Servers," "Media Servers"). These are used to prompt user to what they want to capture.
    Each catagory can have sub catagories which includes an identifier, such as "PCSCF" or "RTPENGINE," along with its `type` (e.g., "ecs" or "ec2") and `id`. `id` is actually the key name of your ECS cluster or EC2 instance which tool looks for to start capture.

    **Example:**

    ```json
    "captureServices": {
        "SIP Servers": {
            "PCSCF": {
                "id": "kamailio-test",
                "type": "ecs"
            }
        },
        "Media Servers": {
            "RTPENGINE": {
                "id": "rtpengine-test",
                "type": "ec2"
            }
        }
    }
    ```
6. Run the script:
    ```bash
    python ecx_capture.py
    ```
6. Follow the on-screen instructions to perform data capture.

#### Note 
⚠️ You need to add required S3 bucket permissions to your service's role.
⚠️ For ECS task, for moving pcap files into S3 bucket, we need to have `aws` cli installed on tasks or we can use a simple script
to upload pcaps to S3. I used a node.js script on my ECS task, because I had node.js installed for my applications. You can find it under pcapScript folder. It would be easy to use it when you are building your image.

``` docker
COPY ./pcapScript /pcapScript
WORKDIR /pcapScript
RUN . ~/.nvm/nvm.sh && npm install
```

## Contributing
Contributions are welcome! Please reach out to me.

## Contact
For any questions or suggestions, please contact the me at [Hossein Yavari](mailto:hyavari26@gmail.com).
