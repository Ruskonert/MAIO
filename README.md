# MAIO: Monitoring All in One
MAIO serves as a tool for conducting remote monitoring by establishing connections to target systems. 

# Overview
Designed to operate in real-time, it facilitates the continuous collection of valuable resource data from the remote environment. 
Users can seamlessly access and analyze various system metrics, enhancing their ability to monitor and manage the health and performance of systems from a centralized location. 
Whether in monitor mode, where data is diligently recorded to a specified file, or in sensor mode, actively gathering system resource data for comprehensive analysis, MAIO empowers users with a flexible and efficient solution for monitoring and optimizing remote systems.

## Usage

```bash
python maio.py [-h] [-u username] [-p password] [--remote-port remote_port]
                       [-i IP:[port]] [--log-level LOG_LEVEL] [-d DELAY]
                       [-s {0,1}] [filename]
```

## Parameter Descriptions

- `-u`, `--user`: SSH username for the connection.
- `-p`, `--password`: Password for the SSH connection.
- `--remote-port`: Set the remote port when the sensor is connecting. Default is MAIO_REMOTE_PORT.
- `-i`: Remote or client IP. Supports the following format: `192.168.2.4`, `192.168.4.110:2004`.
- `--log-level`: Set the logging level. Default is "INFO".
- `-d`, `--delay`: Set the delay for monitoring resources in seconds. Default is 1.
- `-s`, `--system-type`: Set the system mode. `0` for monitor (records data to a file), `1` for sensor (collects system resource data for monitoring).
- `filename`: If provided, collects resource data for the specified process indicated in the filename.