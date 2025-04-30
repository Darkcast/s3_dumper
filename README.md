```

                                         
     ___         _                       
 ___|_  |      _| |_ _ _____ ___ ___ ___ 
|_ -|_  |     | . | | |     | . | -_|  _|
|___|___|_____|___|___|_|_|_|  _|___|_|  
        |_____|             |_|
                                 by Darkcast
```

S3Dumper is a Python tool designed to download all files from an open S3 bucket listing, preserving the folder structure on your local system.

It allows you to fetch files from publicly available S3 buckets and download them in parallel using threads to increase download speed. The files are organized into a directory named after the domain of the provided URL inside a `site/` folder

## Installation

1. Clone or download the repository
2. Install the required dependencies:

## dependencies
Linux:
```
pip3 install requests
```
##  Usage
Run the script with the -u argument to specify the S3 bucket URL. Optionally, use the -t argument to specify the number of concurrent download threads (default is 8)

### Example
```
python3 s3_dumper.py -u https://your-bucket-url.com -t 16
```

-u : URL to the S3 bucket XML listing (required)

-t : Number of concurrent threads for downloading [default: 8] (optional)


This will download all files from the S3 bucket and save them under the site/urlname
