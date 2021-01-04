"""
Copyright (c) 2020  Deltares - Michiel Tukker

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import os
import requests
from datetime import datetime
import ntpath
import time
import hashlib


class VirusTotalObject:
    """Encapsulates the VirusTotal REST api

    Encapsulates the VirusTotal REST api v3.0,  for more information see https://developers.virustotal.com/v3.0/reference

    Attributes:
        api_token: VT API Token
        sha256_hash (str): an SHA256 hash of a file, used as Id on virustotal
        path (str): path to a file
        analysis_id (str): hash/id for a virustotal analysis
        api_url_base (str): base url of the VT Rest API
        headers (str): REST HTTP headers, default matches VT api
    """

    def __init__(self, api_token, sha256_hash=None, path=None):
        """The constructor for VirusTotalObject class.

        Parameters:
            api_token (str): VT API Token
            sha256_hash (str): an SHA256 hash of a file, used as Id on virustotal (optional)
            path (str): path to a file (optional)
        """
        self.api_token = api_token
        self.sha256 = sha256_hash
        self.path = path
        self.analysis_id = None
        self.api_url_base = 'https://www.virustotal.com/api/v3/'
        self.headers = {'x-apikey': self.api_token}
        if (self.path):
            self.filename = ntpath.basename(self.path)
            if self.filename == '':
                raise ValueError("incorrect path")
            if not os.path.isfile(self.path):
                raise ValueError("File doesn't exist")

    @classmethod
    def from_Sha256_hash(cls, api_token, sha256):
        """Constructs a VirusTotalObject from a SHA256 hash.

        Parameters:
            api_token (str): VT API Token
            sha256_hash (str): an SHA256 hash of a file, used as Id on virustotal (optional)
        """
        return cls(api_token, sha256)

    @classmethod
    def from_path(cls, api_token, filepath):
        """Constructs a VirusTotalObject from a file path.

        Parameters:
            api_token (str): VT API Token
            filepath (str): path to a file
        """
        tmp = cls(api_token, path=filepath)
        tmp.sha256 = get_sha256(tmp.path)
        tmp.upload_file()
        return tmp

    def report_error(self, response):
        """Creates an error message and raises the appropriate exception from a http-response object.

        Parameters:
            response (obj): http response object from requests module
        """
        http_response_code = response.status_code
        error_data = json.loads(response.content.decode('utf-8'))
        json_error_code = error_data['error']['code']
        json_error_msg = error_data['error']['message']
        msg = f'Error: Http response={http_response_code}, error code={json_error_code}: {json_error_msg}'
        if http_response_code == 404:
            raise FileNotFoundError(msg)
        if http_response_code == 403:
            raise PermissionError(msg)
        else:
            raise RuntimeError(msg)

    def upload_file(self):
        """Uploads the file to virustotal and sets the file-hash/id attribute and analysis attribute."""
        if not self.filename or not self.path:
            raise ValueError('File path and name not initialized')
        api_url = '{0}files'.format(self.api_url_base)
        response = requests.post(api_url, headers=self.headers, data='', files={
            'file': (self.filename, open(self.path, 'rb'), 'application/vnd.microsoft.portable-executable ')
        })
        if response.status_code == 200:
            json_content = json.loads(response.content.decode('utf-8'))
            id_type = json_content['data']['type']
            if id_type == 'file':
                self.sha256 = json_content['data']['id']
            if id_type == 'analysis':
                self.analysis_id = json_content['data']['id']
        else:
            self.report_error(response)

    def get_file_data(self):
        """Uses the SHA256 hash/id to request the available data from VirusTotal and prints the data to console."""
        if not self.sha256:
            raise ValueError('no id (Sha256 hash) specified')
        api_url = '{0}files/{1}'.format(self.api_url_base, self.sha256)
        response = requests.get(api_url, headers=self.headers)
        if response.status_code == 200:
            json_content = json.loads(response.content.decode('utf-8'))
            filename = json_content['data']['attributes']['names'][0]
            file_version = 'Empty'
            if 'exiftool' in json_content['data']['attributes']:
                if '' in json_content['data']['attributes']['exiftool']:
                    file_version = json_content['data']['attributes']['exiftool']['FileVersion']
            last_analysis_datetime = datetime.utcfromtimestamp(json_content['data']['attributes']['last_analysis_date'])
            last_analysis_dtstr = last_analysis_datetime.strftime('%Y-%m-%d %H:%M:%S')
            analysis_data = json_content['data']['attributes']['last_analysis_results']
            print(f'File: {filename}, version: {file_version}, Last analysis date: {last_analysis_dtstr}')

            detection = False
            for k, v in analysis_data.items():
                analysis_result = v["result"]
                if analysis_result:
                    if not detection:
                        print("\tDetected as malware by: ")
                        detection = True
                    print(f'\t\tAV vendor: {k} - Result: {analysis_result}')
            if not detection:
                print("\tNot detected as Malware")
        else:
            self.report_error(response)

    def run_analysis(self):
        """Uses the SHA256 hash/id to request a new analysis on VirusTotal."""
        if not self.sha256:
            raise ValueError('no id (Sha256 hash) specified')
        api_url = '{0}files/{1}/analyse'.format(self.api_url_base, id)
        response = requests.get(api_url, headers=self.headers)
        if response.status_code == 200:
            json_content = json.loads(response.content.decode('utf-8'))
            self.analysis_id = json_content['data']['id']
        else:
            self.report_error(response)

    def get_analysis(self):
        """Uses the analysis id attribute to request a new analysis on VirusTotal."""
        if not self.analysis_id:
            raise ValueError('no id specified')
        api_url = '{0}analyses/{1}'.format(self.api_url_base, self.analysis_id)
        response = requests.get(api_url, headers=self.headers)
        if response.status_code == 200:
            json_content = json.loads(response.content.decode('utf-8'))
            # print(str(json.dumps(response.content.decode('utf-8'), ensure_ascii=False)))
            self.sha256 = json_content['meta']['file_info']['sha256']
            last_analysis_datetime = datetime.utcfromtimestamp(json_content['data']['attributes']['date'])
            last_analysis_dtstr = last_analysis_datetime.strftime('%Y-%m-%d %H:%M:%S')
            analysis_data = json_content['data']['attributes']['results']
            print(f'File: {self.filename}, Last analysis date: {last_analysis_dtstr}, Hash: {self.sha256}')
            detection = False
            for k, v in analysis_data.items():
                analysis_result = v["result"]
                if analysis_result:
                    if not detection:
                        print("\tDetected as malware by: ")
                        detection = True
                    print(f'\t\tAV vendor: {k} - Result: {analysis_result}')
            if not detection:
                print("\tNot detected as Malware")

            # last_analysis_datetime = datetime.utcfromtimestamp(data['data']['attributes']['last_analysis_date'])
            # print('Last analysis date:' + last_analysis_datetime.strftime('%Y-%m-%d %H:%M:%S'))
            # analysis_data = data['data']['attributes']['last_analysis_results']
            # for k, v in analysis_data.items():
            #     analysis_result = v["result"]
            #     if analysis_result:
            #         print(f'\tAV: {k} - Result: {analysis_result}')
        else:
            self.report_error(response)


def get_sha256(file):
    """calculates and returns the SHA256 hash of a file.

    Parameters:
    file(str): file paths
    """
    sha256_hash = hashlib.sha256()
    with open(file, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


def check_file_hashes(file_list, api_token):
    """Generates a list of Sha256 hashes, which are used as ID's on Virustotal, assumes that the files was already
    uploaded.
    Parameters:
    file_list ([str]): list of file paths to be checked
    api_token (str): API token for VirusTotal
    """
    sha256_list = []
    for filepath in file_list:
        sha256_list.append(get_sha256(filepath))
        print(f'File: {filepath}, hash: {sha256_list[-1]} ')
    first = True
    for hash in sha256_list:
        if first:
            first = False
        else:
            time.sleep(15)
        tmp = VirusTotalObject.from_Sha256_hash(api_token, hash)
        tmp.get_file_data()


def upload_check_files(file_list, api_token):
    """Uploads files to Virustotal and retrieves the latest analysis data
    Parameters:
    file_list ([str]): list of file paths to be checked
    api_token (str): API token for VirusTotal
    """
    vt_objects = []
    first = True
    for filepath in file_list:
        if first:
            first = False
        else:
            time.sleep(15)  # sleep for 15 seconds to prevent overloading the Virustotal API (max 4 requests per minute)
        vt_objects.append(VirusTotalObject.from_path(api_token, filepath))  # 1 request at VT API
        print(f'File: {vt_objects[-1].filename}, hash: {vt_objects[-1].sha256} ')

    first = True
    for item in vt_objects:
        if first:
            first = False
        else:
            time.sleep(15)  # sleep for 15 seconds to prevent overloading the Virustotal API (max 4 requests per minute)
        item.get_analysis()  # 1 request at VT API
